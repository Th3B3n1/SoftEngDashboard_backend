using System.Collections.Concurrent;
using System.Text.Json.Nodes;

namespace Backend.Services;

/// <summary>
/// Proxies Moodle Web Service calls while strictly enforcing:
/// 1. Server-side decryption of the encrypted Moodle token (so the raw wstoken is never stored in the browser).
/// 2. Read-only function allowlist (no write/submission/quiz-attempt functions permitted).
/// 3. Single-course restriction locked to Course ID 16995 (BMEVIMIAB04).
/// </summary>
public class MoodleProxyService(ILogger<MoodleProxyService> logger, IHttpClientFactory httpClientFactory)
{
    private const string AllowedCourseId = "16995";
    private const string MoodleRestUrl = "https://edu.vik.bme.hu/webservice/rest/server.php";

    private static readonly HashSet<string> AllowedTopLevelFunctions = new(StringComparer.Ordinal)
    {
        "core_webservice_get_site_info",
        "core_group_get_course_user_groups",
        "mod_quiz_get_quizzes_by_courses",
        "mod_assign_get_assignments",
        "core_completion_get_activities_completion_status",
        "tool_mobile_call_external_functions"
    };

    private static readonly HashSet<string> AllowedBatchSubFunctions = new(StringComparer.Ordinal)
    {
        "mod_quiz_get_user_best_grade",
        "mod_quiz_get_user_attempts",
        "mod_assign_get_submission_status"
    };

    // Cache of quiz IDs and assignment IDs confirmed to belong to Course 550
    private static readonly ConcurrentDictionary<int, byte> Course550QuizIds = new();
    private static readonly ConcurrentDictionary<int, byte> Course550AssignIds = new();

    public async Task<(int StatusCode, string ContentJson)> ExecuteReadOnlyCourse550CallAsync(
        IFormCollection form,
        CancellationToken ct = default)
    {
        string? rawTokenInput = form["wstoken"].FirstOrDefault();
        string? wsToken = MoodleTokenCrypto.Unprotect(rawTokenInput);
        if (string.IsNullOrEmpty(wsToken))
        {
            return (StatusCodes.Status200OK, """{"exception":"moodle_exception","errorcode":"invalidtoken","message":"Érvénytelen vagy lejárt munkamenet token."}""");
        }

        string? wsFunction = form["wsfunction"].FirstOrDefault();
        if (string.IsNullOrEmpty(wsFunction) || !AllowedTopLevelFunctions.Contains(wsFunction))
        {
            logger.LogWarning("Blocked disallowed Moodle wsfunction: {Fn}", wsFunction);
            return (StatusCodes.Status403Forbidden, """{"exception":"moodle_exception","errorcode":"forbidden_scope","message":"Ez a Moodle művelet biztonsági okokból le van tiltva (csak olvasási hozzáférés engedélyezett)."}""");
        }

        // Enforce Course 16995 scope on course-level functions
        if (!ValidateCourseScope(wsFunction, form, out string? scopeError))
        {
            logger.LogWarning("Blocked Moodle call outside course 16995 ({Fn}): {Reason}", wsFunction, scopeError);
            return (StatusCodes.Status403Forbidden, """{"exception":"moodle_exception","errorcode":"forbidden_scope","message":"Hozzáférés megtagadva: a token kizárólag a Szoftvertechnológia (16995) kurzushoz használható."}""");
        }

        // Build outgoing form payload with decrypted wstoken
        List<KeyValuePair<string, string>> forwardParams = new(form.Count + 1)
        {
            new KeyValuePair<string, string>("wstoken", wsToken)
        };

        foreach (KeyValuePair<string, Microsoft.Extensions.Primitives.StringValues> kv in form)
        {
            if (string.Equals(kv.Key, "wstoken", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }
            foreach (string? val in kv.Value)
            {
                if (val != null)
                {
                    forwardParams.Add(new KeyValuePair<string, string>(kv.Key, val));
                }
            }
        }

        HttpClient client = httpClientFactory.CreateClient("MoodleApi");
        using FormUrlEncodedContent content = new FormUrlEncodedContent(forwardParams);
        using HttpResponseMessage resp = await client.PostAsync(MoodleRestUrl, content, ct);
        string body = await resp.Content.ReadAsStringAsync(ct);

        if (resp.IsSuccessStatusCode)
        {
            TrackCourse550ModuleIds(wsFunction, body);
        }

        return ((int)resp.StatusCode, body);
    }

    private static bool ValidateCourseScope(string wsFunction, IFormCollection form, out string? reason)
    {
        reason = null;

        switch (wsFunction)
        {
            case "core_webservice_get_site_info":
                return true;

            case "core_group_get_course_user_groups":
            case "core_completion_get_activities_completion_status":
            {
                string? courseId = form["courseid"].FirstOrDefault();
                if (courseId != AllowedCourseId)
                {
                    reason = $"courseid={courseId}";
                    return false;
                }
                return true;
            }

            case "mod_quiz_get_quizzes_by_courses":
            case "mod_assign_get_assignments":
            {
                // Must only query courseids[0]=550 and no other courseids
                string? c0 = form["courseids[0]"].FirstOrDefault();
                if (c0 != AllowedCourseId)
                {
                    reason = $"courseids[0]={c0}";
                    return false;
                }
                foreach (string key in form.Keys)
                {
                    if (key.StartsWith("courseids[", StringComparison.Ordinal) && key != "courseids[0]")
                    {
                        reason = $"Extra courseid key {key}";
                        return false;
                    }
                }
                return true;
            }

            case "tool_mobile_call_external_functions":
            {
                // Inspect every requests[i][function] and requests[i][arguments]
                foreach (string key in form.Keys)
                {
                    if (key.EndsWith("][function]", StringComparison.Ordinal))
                    {
                        string? subFn = form[key].FirstOrDefault();
                        if (string.IsNullOrEmpty(subFn) || !AllowedBatchSubFunctions.Contains(subFn))
                        {
                            reason = $"Disallowed batch function: {subFn}";
                            return false;
                        }

                        string prefix = key[..^"[function]".Length];
                        string argsKey = prefix + "[arguments]";
                        string? argsJson = form[argsKey].FirstOrDefault();
                        if (string.IsNullOrWhiteSpace(argsJson))
                        {
                            reason = "Missing batch arguments";
                            return false;
                        }

                        try
                        {
                            JsonNode? argsNode = JsonNode.Parse(argsJson);
                            if (subFn is "mod_quiz_get_user_best_grade" or "mod_quiz_get_user_attempts")
                            {
                                int quizId = argsNode?["quizid"]?.GetValue<int>() ?? 0;
                                if (quizId <= 0 || (!Course550QuizIds.IsEmpty && !Course550QuizIds.ContainsKey(quizId)))
                                {
                                    reason = $"Quiz ID {quizId} is not in Course 550";
                                    return false;
                                }
                            }
                            else if (subFn == "mod_assign_get_submission_status")
                            {
                                int assignId = argsNode?["assignid"]?.GetValue<int>() ?? 0;
                                if (assignId <= 0 || (!Course550AssignIds.IsEmpty && !Course550AssignIds.ContainsKey(assignId)))
                                {
                                    reason = $"Assign ID {assignId} is not in Course 550";
                                    return false;
                                }
                            }
                        }
                        catch
                        {
                            reason = "Invalid JSON in batch arguments";
                            return false;
                        }
                    }
                }
                return true;
            }

            default:
                reason = "Unknown function";
                return false;
        }
    }

    private static void TrackCourse550ModuleIds(string wsFunction, string responseJson)
    {
        try
        {
            if (wsFunction == "mod_quiz_get_quizzes_by_courses")
            {
                JsonNode? root = JsonNode.Parse(responseJson);
                if (root?["quizzes"] is JsonArray quizzes)
                {
                    foreach (JsonNode? q in quizzes)
                    {
                        int id = q?["id"]?.GetValue<int>() ?? 0;
                        if (id > 0)
                        {
                            Course550QuizIds.TryAdd(id, 1);
                        }
                    }
                }
            }
            else if (wsFunction == "mod_assign_get_assignments")
            {
                JsonNode? root = JsonNode.Parse(responseJson);
                if (root?["courses"] is JsonArray courses)
                {
                    foreach (JsonNode? c in courses)
                    {
                        if (c?["assignments"] is JsonArray assigns)
                        {
                            foreach (JsonNode? a in assigns)
                            {
                                int id = a?["id"]?.GetValue<int>() ?? 0;
                                if (id > 0)
                                {
                                    Course550AssignIds.TryAdd(id, 1);
                                }
                            }
                        }
                    }
                }
            }
        }
        catch
        {
            // Ignore non-JSON or exception responses
        }
    }
}


using System.ComponentModel.DataAnnotations;

namespace Backend.DTOs;

public record HfStatusRequestDto(
    [param:
        Required(ErrorMessage = "Az ltik token megadása kötelező"),
        StringLength(4096, MinimumLength = 10, ErrorMessage = "A token hossza érvénytelen"),
        RegularExpression(@"^[A-Za-z0-9\-_.\~]+$", ErrorMessage = "A token formátuma érvénytelen")] string Ltik
);

public record HfSyncByMoodleTokenRequestDto(
    [param:
        Required(ErrorMessage = "A Moodle token megadása kötelező"),
        StringLength(512, MinimumLength = 32, ErrorMessage = "Érvénytelen Moodle token hossz"),
        RegularExpression(@"^(enc:[A-Za-z0-9\-_]+|[0-9a-fA-F]{32})$", ErrorMessage = "Érvénytelen Moodle token formátum")] string WsToken
);

public record ProtectTokenRequestDto(
    [param:
        Required(ErrorMessage = "A Moodle token megadása kötelező"),
        StringLength(512, MinimumLength = 32, ErrorMessage = "Érvénytelen Moodle token hossz"),
        RegularExpression(@"^(enc:[A-Za-z0-9\-_]+|[0-9a-fA-F]{32})$", ErrorMessage = "Érvénytelen Moodle token formátum")] string Token
);



using System.ComponentModel.DataAnnotations;

namespace Backend.DTOs;

public record LoginRequestDto(
    [param:
        Required(ErrorMessage = "A felhasználónév megadása kötelező"),
        StringLength(100, ErrorMessage = "A felhasználónév nem lehet hosszabb {1} karakternél")] string Username,
    [param:
        Required(ErrorMessage = "A jelszó megadása kötelező"),
        StringLength(255, ErrorMessage = "A jelszó nem lehet hosszabb {1} karakternél")] string Password
);

public record LoginResponseDto(
    string Token,
    int UserId,
    string FullName,
    string Username,
    string? Ltik = null
);

public record ProtectTokenRequestDto(
    [param:
        Required(ErrorMessage = "A Moodle token megadása kötelező"),
        StringLength(512, MinimumLength = 32, ErrorMessage = "Érvénytelen Moodle token hossz"),
        RegularExpression(@"^(enc:[A-Za-z0-9\-_]+|[0-9a-fA-F]{32})$", ErrorMessage = "Érvénytelen Moodle token formátum")] string Token
);

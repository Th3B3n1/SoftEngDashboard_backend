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


using System.ComponentModel.DataAnnotations;

namespace Backend.DTOs;

public record HfStatusRequestDto(
    [param:
        Required(ErrorMessage = "Az ltik token megadása kötelező"),
        StringLength(4096, MinimumLength = 10, ErrorMessage = "A token hossza érvénytelen"),
        RegularExpression(@"^[A-Za-z0-9\-_.\~]+$", ErrorMessage = "A token formátuma érvénytelen")] string Ltik
);


using System.ComponentModel.DataAnnotations;

namespace Backend.DTOs;

public record HfStatusRequestDto(
    [param:
        Required(ErrorMessage = "Az ltik token megadása kötelező"),
        StringLength(4096, ErrorMessage = "A token hossza érvénytelen")] string Ltik
);


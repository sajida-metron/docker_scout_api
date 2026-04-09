"""Parse image query strings into ImageRef."""

from docker_scout_api.models import ImageRef


def parse_image_spec(spec: str) -> ImageRef:
    """
    Parse ``namespace/repo:tag`` or ``repo:tag`` (library namespace).

    Raises:
        ValueError: If the string cannot be parsed.
    """
    spec = spec.strip()
    if not spec or spec.lower() == "all":
        raise ValueError("use discover mode for 'all', not parse_image_spec")
    if ":" not in spec:
        raise ValueError("Image must include a tag, e.g. myorg/myapp:1.0 or nginx:latest")
    name_part, tag = spec.rsplit(":", 1)
    if not name_part or not tag:
        raise ValueError("Invalid image reference")
    if "/" in name_part:
        org, repo = name_part.split("/", 1)
        if not org or not repo:
            raise ValueError("Invalid namespace/repository")
    else:
        org, repo = "library", name_part
    return ImageRef(org=org.strip(), repo=repo.strip(), tag=tag.strip())

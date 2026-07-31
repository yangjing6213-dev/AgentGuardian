from pathlib import Path
from xml.etree import ElementTree

from PIL import Image


ROOT = Path(__file__).resolve().parents[1]
BRAND = ROOT / "assets" / "brand"


def luminance(hex_color: str) -> float:
    channels = [int(hex_color[index : index + 2], 16) / 255 for index in (1, 3, 5)]
    linear = [value / 12.92 if value <= 0.04045 else ((value + 0.055) / 1.055) ** 2.4 for value in channels]
    return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]


def contrast(first: str, second: str) -> float:
    light, dark = sorted((luminance(first), luminance(second)), reverse=True)
    return (light + 0.05) / (dark + 0.05)


def main() -> None:
    expected_svg = {
        "agentguardian-mark.svg": (0, 0, 512, 512),
        "agentguardian-mark-dark.svg": (0, 0, 512, 512),
        "agentguardian-wordmark.svg": (0, 0, 1600, 400),
        "agentguardian-cover.svg": (0, 0, 1280, 640),
    }
    for name, view_box in expected_svg.items():
        root = ElementTree.parse(BRAND / name).getroot()
        assert root.tag.endswith("svg"), name
        assert tuple(map(int, root.attrib["viewBox"].split())) == view_box, name
        raw = (BRAND / name).read_text(encoding="utf-8")
        assert "href=" not in raw and "<image" not in raw, name

    with Image.open(BRAND / "agentguardian-mark-512.png") as image:
        assert image.size == (512, 512)
        assert image.mode == "RGBA"
    with Image.open(BRAND / "agentguardian-mark-dark-512.png") as image:
        assert image.size == (512, 512)
        assert image.mode in {"RGB", "RGBA"}
    with Image.open(BRAND / "agentguardian-cover-1280x640.png") as image:
        assert image.size == (1280, 640)
        assert image.mode in {"RGB", "RGBA"}

    for accent in ("#48B7F2", "#079CF0", "#00B37A", "#FF5B20", "#FFC04D"):
        assert contrast(accent, "#1F2428") >= 4.5, accent
    assert contrast("#1F2428", "#FFFFFF") >= 4.5
    assert contrast("#D43F13", "#FFFFFF") >= 4.5
    assert contrast("#D43F13", "#FFFDF9") >= 4.5
    assert contrast("#B97800", "#FFFDF9") >= 3.0
    cover = (BRAND / "agentguardian-cover.svg").read_text(encoding="utf-8")
    assert "SYNTHETIC DEMO" in cover


if __name__ == "__main__":
    main()

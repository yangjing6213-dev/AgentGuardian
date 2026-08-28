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

    assert contrast("#21C786", "#0F1215") >= 4.5
    assert contrast("#0F1215", "#F4F6F7") >= 4.5
    assert contrast("#AAB4BB", "#0F1215") >= 4.5
    assert contrast("#F0BD5C", "#171C20") >= 4.5
    assert contrast("#EF7167", "#171C20") >= 4.5
    cover = (BRAND / "agentguardian-cover.svg").read_text(encoding="utf-8")
    for color in ("#0F1215", "#171C20", "#394149", "#21C786", "#AAB4BB", "#F0BD5C", "#EF7167"):
        assert color in cover, color
    assert "synthetic audit data" in cover
    assert "审阅修复方案" in cover
    assert "查看人工解决方案" not in cover
    assert "rx=" not in cover


if __name__ == "__main__":
    main()

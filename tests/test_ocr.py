from PIL import Image
from screenshield.core.ocr import OCRPipeline


def test_preprocess_returns_image():
    img = Image.new("RGB", (100, 50), color=(255, 255, 255))
    result = OCRPipeline().preprocess(img)
    assert isinstance(result, Image.Image)


def test_extract_text_returns_string():
    img = Image.new("RGB", (200, 100), color=(255, 255, 255))
    text = OCRPipeline().extract_text(img)
    assert isinstance(text, str)

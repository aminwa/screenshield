import pytesseract
import numpy as np
import cv2
from PIL import Image, ImageFilter


class OCRPipeline:
    def preprocess(self, image: Image.Image) -> Image.Image:
        # upscale first — tesseract accuracy drops sharply below ~150dpi equivalent
        w, h = image.size
        image = image.resize((w * 2, h * 2), Image.LANCZOS)
        img = np.array(image.convert("L"))
        # adaptive threshold handles dark terminal backgrounds better than global
        thresh = cv2.adaptiveThreshold(
            img, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 31, 10
        )
        result = Image.fromarray(thresh)
        return result.filter(ImageFilter.SHARPEN)

    def extract_text(self, image: Image.Image) -> str:
        processed = self.preprocess(image)
        # psm 6 = assume uniform block of text, works better for terminal output
        return pytesseract.image_to_string(processed, config="--psm 6")

    def extract_with_boxes(self, image: Image.Image) -> list[dict]:
        processed = self.preprocess(image)
        data = pytesseract.image_to_data(processed, output_type=pytesseract.Output.DICT)
        boxes = []
        for i, word in enumerate(data["text"]):
            if word.strip():
                boxes.append({
                    "text": word,
                    "x": data["left"][i],
                    "y": data["top"][i],
                    "w": data["width"][i],
                    "h": data["height"][i],
                })
        return boxes

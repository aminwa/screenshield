import pytesseract
import numpy as np
import cv2
from PIL import Image, ImageFilter


class OCRPipeline:
    def preprocess(self, image: Image.Image) -> Image.Image:
        img = np.array(image.convert("L"))
        # adaptive threshold handles mixed lighting better than global
        thresh = cv2.adaptiveThreshold(
            img, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 11, 2
        )
        result = Image.fromarray(thresh)
        return result.filter(ImageFilter.SHARPEN)

    def extract_text(self, image: Image.Image) -> str:
        processed = self.preprocess(image)
        return pytesseract.image_to_string(processed)

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

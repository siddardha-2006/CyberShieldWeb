import base64
import io
import re
from typing import Dict, Any, Optional
from PIL import Image
import cv2
import numpy as np


class QrExtractor:
    @classmethod
    def extract(cls, image_base64: Optional[str] = None, decoded_payload: Optional[str] = None) -> Dict[str, Any]:
        payload = decoded_payload or ""
        
        if not payload and image_base64:
            try:
                # Strip data URL prefix if present
                clean_b64 = re.sub(r'^data:image/.+;base64,', '', image_base64)
                img_data = base64.b64decode(clean_b64)
                
                # Convert to numpy array for OpenCV QRCodeDetector
                image = Image.open(io.BytesIO(img_data)).convert('RGB')
                open_cv_image = np.array(image)
                # Convert RGB to BGR
                open_cv_image = open_cv_image[:, :, ::-1].copy()
                
                detector = cv2.QRCodeDetector()
                data, bbox, _ = detector.detectAndDecode(open_cv_image)
                if data:
                    payload = data
            except Exception:
                pass
                
        payload_type = "empty"
        if payload.startswith("http://") or payload.startswith("https://"):
            payload_type = "url"
        elif payload.startswith("WIFI:"):
            payload_type = "wifi_config"
        elif payload.startswith("smsto:") or payload.startswith("sms:"):
            payload_type = "sms"
        elif payload.startswith("mailto:"):
            payload_type = "email"
        elif payload:
            payload_type = "text"
            
        return {
            "decoded_payload": payload,
            "payload_type": payload_type,
            "is_url": payload_type == "url",
            "payload_length": len(payload)
        }


import requests
import re
import lxml.html
import os
from fastapi import FastAPI, HTTPException, Body, Depends, Security # Убран Header, если не нужен в других местах
from fastapi.security import APIKeyHeader # <-- Добавлен импорт
from pydantic import BaseModel, Field, HttpUrl
from bs4 import BeautifulSoup
from typing import Dict, Optional, List, Union, Any
from enum import Enum
from dotenv import load_dotenv

load_dotenv()

# --- Константы и конфигурация ---
API_KEY_HEADER_NAME = "X-API-Key"
EXPECTED_API_KEY = os.getenv("API_KEY")

# ---> СОЗДАЕМ СХЕМУ ДЛЯ API КЛЮЧА В ЗАГОЛОВКЕ <---
api_key_header_scheme = APIKeyHeader(name=API_KEY_HEADER_NAME, auto_error=False)

# --- Модели данных ---
class SelectorType(str, Enum):
    CSS = "css"
    XPATH = "xpath"
    REGEX = "regex"

class SelectorDefinition(BaseModel):
    type: SelectorType = Field(..., description="Тип селектора: css, xpath или regex")
    value: str = Field(..., description="Строка селектора/выражения")
    get_all: bool = Field(False, description="Извлечь все совпадения (True) или только первое (False). Для Regex всегда извлекаются все совпадения группы 1 или 0.")

class ParseOptions(BaseModel):
    text_only: bool = Field(True, description="Для CSS/XPath: Извлекать только текст, без HTML тегов. Не влияет на Regex.")

class ParseRequest(BaseModel):
    url: HttpUrl
    selectors: Dict[str, SelectorDefinition]
    options: Optional[ParseOptions] = ParseOptions()

class ParseResponseData(BaseModel):
    data: Dict[str, Union[str, List[str], None]]

class ErrorResponse(BaseModel):
    detail: str

# --- Функция-зависимость для проверки API ключа (ОБНОВЛЕНА) ---
async def verify_api_key(api_key_header: Optional[str] = Security(api_key_header_scheme)): # <-- ИСПОЛЬЗУЕМ СХЕМУ
    """Проверяет наличие и правильность API ключа в заголовке."""
    if not EXPECTED_API_KEY:
        raise HTTPException(
            status_code=500,
            detail="Внутренняя ошибка сервера: API ключ не настроен."
        )
    if api_key_header is None:
        raise HTTPException(
            status_code=401,
            detail=f"Требуется API ключ в заголовке '{API_KEY_HEADER_NAME}'"
        )
    if api_key_header != EXPECTED_API_KEY:
        raise HTTPException(
            status_code=403,
            detail="Неверный API ключ"
        )
    return True

# --- Инициализация FastAPI ---
app = FastAPI(
    title="Secure Advanced Web Parser API",
    description="Принимает URL и селекторы (CSS, XPath, Regex), возвращает спарсенный контент. Требует API ключ.",
    version="1.2.1", # Повысим минорную версию
)

# --- Основной эндпоинт для парсинга ---
@app.post(
    "/parse",
    response_model=ParseResponseData,
    responses={
        401: {"model": ErrorResponse, "description": "API ключ отсутствует"},
        403: {"model": ErrorResponse, "description": "Неверный API ключ"},
        400: {"model": ErrorResponse, "description": "Ошибка во входных данных"},
        422: {"model": ErrorResponse, "description": "Невалидные входные данные"},
        500: {"model": ErrorResponse, "description": "Ошибка сервера (включая загрузку/парсинг/настройку)"},
        504: {"model": ErrorResponse, "description": "Таймаут при загрузке URL"}
    },
    dependencies=[Depends(verify_api_key)] # Зависимость остается здесь
)
async def parse_url(request_data: ParseRequest = Body(...)):
    """
    Парсит веб-страницу по заданному URL и набору селекторов (CSS, XPath, Regex).
    **Требует валидный API ключ в заголовке X-API-Key.**
    """
    # --- Код парсинга остается без изменений ---
    url = str(request_data.url)
    selectors_config = request_data.selectors
    options = request_data.options if request_data.options else ParseOptions()

    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }

    try:
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status()
        content_bytes = response.content
        encoding = response.apparent_encoding or 'utf-8'
        html_text = content_bytes.decode(encoding, errors='replace')

    except requests.exceptions.Timeout:
        raise HTTPException(status_code=504, detail=f"Не удалось загрузить URL: Таймаут ({url})")
    except requests.exceptions.RequestException as e:
        raise HTTPException(status_code=500, detail=f"Ошибка при загрузке URL {url}: {e}")
    except Exception as e:
         raise HTTPException(status_code=500, detail=f"Ошибка при получении или декодировании контента URL {url}: {e}")

    parsed_data: Dict[str, Union[str, List[str], None]] = {}

    try:
        soup = None
        html_tree = None

        for key, selector_def in selectors_config.items():
            selector_type = selector_def.type
            selector_value = selector_def.value
            get_all = selector_def.get_all
            results = []

            try:
                if selector_type == SelectorType.CSS:
                    if soup is None: soup = BeautifulSoup(html_text, 'lxml')
                    elements = soup.select(selector_value)
                    if elements:
                        limit = len(elements) if get_all else 1
                        for i in range(limit):
                            element = elements[i]
                            if options.text_only:
                                text = element.get_text(strip=True)
                                if text: results.append(text)
                            else:
                                results.append(str(element))

                elif selector_type == SelectorType.XPATH:
                    if html_tree is None: html_tree = lxml.html.fromstring(content_bytes)
                    elements = html_tree.xpath(selector_value)
                    if elements:
                        limit = len(elements) if get_all else 1
                        count = 0
                        for i in range(len(elements)):
                            if count >= limit: break
                            element = elements[i]
                            if isinstance(element, lxml.html.HtmlElement):
                                if options.text_only:
                                    text = element.text_content().strip()
                                    if text:
                                        results.append(text)
                                        count += 1
                                else:
                                    results.append(lxml.html.tostring(element, encoding='unicode').strip())
                                    count += 1
                            elif isinstance(element, str):
                                cleaned_str = element.strip()
                                if cleaned_str:
                                    results.append(cleaned_str)
                                    count += 1
                            else:
                                maybe_str = str(element).strip()
                                if maybe_str:
                                    results.append(maybe_str)
                                    count += 1

                elif selector_type == SelectorType.REGEX:
                    matches_found = 0
                    for match in re.finditer(selector_value, html_text):
                        if not get_all and matches_found >= 1: break
                        try: extracted = match.group(1)
                        except IndexError: extracted = match.group(0)
                        if extracted is not None:
                            cleaned_match = extracted.strip()
                            if cleaned_match:
                                results.append(cleaned_match)
                                matches_found += 1

            except Exception as e:
                print(f"Ошибка обработки селектора для ключа '{key}' (тип: {selector_type}, значение: '{selector_value}'): {e}")
                results = [f"Ошибка обработки: {e}"]

            if not results:
                parsed_data[key] = None
            elif len(results) == 1 and not get_all and selector_type != SelectorType.REGEX:
                 parsed_data[key] = results[0]
            else:
                parsed_data[key] = results

    except lxml.etree.ParserError as e:
         raise HTTPException(status_code=500, detail=f"Ошибка парсинга HTML с помощью lxml: {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Общая ошибка парсинга для URL {url}: {e}")

    return ParseResponseData(data=parsed_data)

# --- Корневой эндпоинт ---
@app.get("/")
async def read_root():
    return {"message": "Привет! Это расширенный сервис парсинга. Используй эндпоинт /parse (POST). Требуется API ключ."}
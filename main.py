# Файл: main.py

import requests
import re
import lxml.html
import os
from fastapi import FastAPI, HTTPException, Body, Depends, Security
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field, HttpUrl
from bs4 import BeautifulSoup
from typing import Dict, Optional, List, Union, Any
from enum import Enum
from dotenv import load_dotenv

# --- Загружаем переменные из .env файла ---
load_dotenv()

# --- Константы и конфигурация ---
API_KEY_HEADER_NAME = "X-API-Key"
EXPECTED_API_KEY = os.getenv("API_KEY")
api_key_header_scheme = APIKeyHeader(name=API_KEY_HEADER_NAME, auto_error=False)

# --- Модели данных ---
class SelectorType(str, Enum):
    CSS = "css"
    XPATH = "xpath"
    REGEX = "regex"

class SelectorDefinition(BaseModel):
    type: SelectorType = Field(..., description="Тип селектора: css, xpath или regex")
    value: str = Field(..., description="Строка селектора/выражения")
    get_all: bool = Field(False, description="Извлечь все совпадения (True) или только первое (False).")
    text_only: Optional[bool] = Field(None, description="Переопределить глобальную настройку text_only для этого селектора.")

class ParseOptions(BaseModel):
    text_only: bool = Field(True, description="Глобальная настройка: Извлекать только текст (True) или HTML (False).")
    follow_redirects: bool = Field(True, description="Следовать ли HTTP редиректам (3xx)?")

class ParseRequest(BaseModel):
    url: HttpUrl
    selectors: Dict[str, SelectorDefinition]
    options: Optional[ParseOptions] = ParseOptions()

class ParseResponseData(BaseModel):
    status_code: int = Field(..., description="Финальный HTTP статус код ответа сервера")
    # ---> ИЗМЕНЕНИЕ: Добавляем опциональные поля для URL редиректов <---
    redirect_location: Optional[str] = Field(None, description="URL из заголовка Location, если остановились на редиректе (status 3xx, follow_redirects=false)")
    final_url: Optional[str] = Field(None, description="Конечный URL после всех редиректов (если они были и follow_redirects=true)")
    data: Dict[str, Union[str, List[str], None]]

class ErrorResponse(BaseModel):
    detail: str

# --- Функция-зависимость для проверки API ключа ---
async def verify_api_key(api_key_header: Optional[str] = Security(api_key_header_scheme)):
    if not EXPECTED_API_KEY:
        raise HTTPException(status_code=500, detail="Внутренняя ошибка сервера: API ключ не настроен.")
    if api_key_header is None:
        raise HTTPException(status_code=401, detail=f"Требуется API ключ в заголовке '{API_KEY_HEADER_NAME}'")
    if api_key_header != EXPECTED_API_KEY:
        raise HTTPException(status_code=403, detail="Неверный API ключ")
    return True

# --- Инициализация FastAPI ---
app = FastAPI(
    title="Super Secure Advanced Web Parser API",
    description="Принимает URL и селекторы, возвращает контент, статус код и информацию о редиректах. Требует API ключ.",
    version="1.4.0", # Обновим версию
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
        500: {"model": ErrorResponse, "description": "Ошибка сервера"},
        504: {"model": ErrorResponse, "description": "Таймаут при загрузке URL"}
    },
    dependencies=[Depends(verify_api_key)]
)
async def parse_url(request_data: ParseRequest = Body(...)):
    """
    Парсит веб-страницу по URL и селекторам.
    Управляет редиректами, настройками text_only и возвращает информацию о редиректах.
    **Требует валидный API ключ в заголовке X-API-Key.**
    """
    initial_url = str(request_data.url) # Сохраняем исходный URL
    selectors_config = request_data.selectors
    options = request_data.options if request_data.options else ParseOptions()

    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }

    final_status_code = None
    response = None
    redirect_location_url: Optional[str] = None # ---> ИЗМЕНЕНИЕ: Переменная для Location
    actual_final_url: Optional[str] = None    # ---> ИЗМЕНЕНИЕ: Переменная для конечного URL

    try:
        # 1. Загружаем страницу
        response = requests.get(
            initial_url,
            headers=headers,
            timeout=15,
            allow_redirects=options.follow_redirects
        )
        final_status_code = response.status_code
        actual_final_url = response.url # ---> ИЗМЕНЕНИЕ: Получаем конечный URL из response

        # Проверяем статус
        if options.follow_redirects:
             response.raise_for_status() # Ошибка для не-2xx
        elif final_status_code >= 400:
             response.raise_for_status() # Ошибка для 4xx/5xx, если редиректы отключены

        # ---> ИЗМЕНЕНИЕ: Извлекаем Location, если остановились на редиректе <---
        if not options.follow_redirects and 300 <= final_status_code < 400:
            redirect_location_url = response.headers.get('Location')

        # ---> ИЗМЕНЕНИЕ: Убираем final_url из ответа, если он совпадает с исходным <---
        if actual_final_url == initial_url:
             actual_final_url = None # Не было редиректов или они не отслеживались

        # Если дошли сюда, статус либо 2xx, либо 3xx (при follow_redirects=False)
        content_bytes = response.content
        encoding = response.apparent_encoding or 'utf-8'
        html_text = content_bytes.decode(encoding, errors='replace')

    except requests.exceptions.Timeout:
        raise HTTPException(status_code=504, detail=f"Не удалось загрузить URL: Таймаут ({initial_url})")
    except requests.exceptions.RequestException as e:
        status_to_raise = final_status_code
        if status_to_raise is None and hasattr(e, 'response') and e.response is not None:
             status_to_raise = e.response.status_code
        if status_to_raise is None: status_to_raise = 500

        detail_msg = f"Ошибка при загрузке URL {initial_url}: {e}"
        if final_status_code: detail_msg += f" (Статус код: {final_status_code})"

        raise HTTPException(status_code=status_to_raise, detail=detail_msg)
    except Exception as e:
         raise HTTPException(status_code=500, detail=f"Ошибка при получении или декодировании контента URL {initial_url}: {e}")

    if final_status_code is None: final_status_code = 0

    # 2. Парсинг
    parsed_data: Dict[str, Union[str, List[str], None]] = {}
    should_parse = (final_status_code >= 200 and final_status_code < 300) or \
                   (not options.follow_redirects and final_status_code >= 300 and final_status_code < 400)

    if should_parse and html_text:
        try:
            soup = None
            html_tree = None
            for key, selector_def in selectors_config.items():
                # ... (внутренний код цикла парсинга остается БЕЗ ИЗМЕНЕНИЙ) ...
                selector_type = selector_def.type
                selector_value = selector_def.value
                get_all = selector_def.get_all
                effective_text_only = selector_def.text_only if selector_def.text_only is not None else options.text_only
                results = []
                try:
                    if selector_type == SelectorType.CSS:
                        if soup is None: soup = BeautifulSoup(html_text, 'lxml')
                        elements = soup.select(selector_value)
                        if elements:
                            limit = len(elements) if get_all else 1
                            for i in range(limit):
                                element = elements[i]
                                if effective_text_only:
                                    text = element.get_text(strip=True)
                                    if text: results.append(text)
                                else:
                                    results.append(str(element)) # Возвращаем HTML
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
                                    if effective_text_only:
                                        text = element.text_content().strip()
                                        if text: results.append(text); count += 1
                                    else:
                                        results.append(lxml.html.tostring(element, encoding='unicode').strip()); count += 1
                                elif isinstance(element, str):
                                    cleaned_str = element.strip()
                                    if cleaned_str: results.append(cleaned_str); count += 1
                                else:
                                    maybe_str = str(element).strip()
                                    if maybe_str: results.append(maybe_str); count += 1
                    elif selector_type == SelectorType.REGEX:
                        matches_found = 0
                        for match in re.finditer(selector_value, html_text):
                            if not get_all and matches_found >= 1: break
                            try: extracted = match.group(1)
                            except IndexError: extracted = match.group(0)
                            if extracted is not None:
                                cleaned_match = extracted.strip()
                                if cleaned_match: results.append(cleaned_match); matches_found += 1
                except Exception as e:
                    print(f"Ошибка обработки селектора для ключа '{key}' (тип: {selector_type}, значение: '{selector_value}'): {e}")
                    results = [f"Ошибка обработки: {e}"]
                if not results: parsed_data[key] = None
                elif len(results) == 1 and not get_all and selector_type != SelectorType.REGEX: parsed_data[key] = results[0]
                else: parsed_data[key] = results
        except lxml.etree.ParserError as e:
             print(f"Ошибка парсинга HTML (lxml) для URL {initial_url}: {e}")
             raise HTTPException(status_code=500, detail=f"Ошибка парсинга HTML (lxml) для URL {initial_url}: {e}")
        except Exception as e:
            print(f"Общая ошибка парсинга для URL {initial_url}: {e}")
            raise HTTPException(status_code=500, detail=f"Общая ошибка парсинга для URL {initial_url}: {e}")

    # 3. Возвращаем результат
    return ParseResponseData(
        status_code=final_status_code,
        # ---> ИЗМЕНЕНИЕ: Добавляем новые поля в ответ <---
        redirect_location=redirect_location_url,
        final_url=actual_final_url,
        data=parsed_data
    )

# --- Корневой эндпоинт ---
@app.get("/")
async def read_root():
    return {"message": "Привет! Это расширенный сервис парсинга. Используй эндпоинт /parse (POST). Требуется API ключ."}
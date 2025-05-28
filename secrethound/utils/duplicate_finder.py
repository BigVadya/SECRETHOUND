import json
import hashlib
import re
from pathlib import Path
from typing import Dict, List, Tuple, Set
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from difflib import SequenceMatcher

# Определяем путь к папке output
OUTPUT_DIR = Path('output')

class DuplicateFinder:
    """
    Класс для поиска дубликатов в результатах сканирования.
    Анализирует найденные чувствительные данные на схожесть.
    """
    def __init__(self, similarity_threshold: float = 0.85):
        """
        Инициализация поисковика дубликатов.
        
        Args:
            similarity_threshold: Порог схожести данных (от 0 до 1)
        """
        self.similarity_threshold = similarity_threshold
        self.console = Console()
        self.content_hashes: Dict[str, List[Dict]] = {}
        
    def _calculate_content_hash(self, content: str) -> str:
        """
        Вычисляет хеш содержимого после нормализации.
        
        Args:
            content: Текст для хеширования
            
        Returns:
            str: MD5 хеш нормализованного текста
        """
        # Нормализуем текст:
        # 1. Приводим к нижнему регистру
        # 2. Удаляем лишние пробелы
        # 3. Удаляем специальные символы
        # 4. Нормализуем URL и пути
        normalized = content.lower().strip()
        normalized = re.sub(r'\s+', ' ', normalized)
        normalized = re.sub(r'[^\w\s]', '', normalized)
        normalized = re.sub(r'(https?://)?(www\.)?', '', normalized)
        normalized = re.sub(r'\.internal\.', 'internal', normalized)
        return hashlib.md5(normalized.encode()).hexdigest()
        
    def _calculate_similarity(self, str1: str, str2: str) -> float:
        """
        Вычисляет схожесть между двумя строками.
        
        Args:
            str1: Первая строка
            str2: Вторая строка
            
        Returns:
            float: Коэффициент схожести от 0 до 1
        """
        return SequenceMatcher(None, str1, str2).ratio()
        
    def find_duplicates(self, scan_results: List[Dict]) -> List[Tuple[Dict, Dict, float]]:
        """
        Находит дубликаты в результатах сканирования.
        
        Args:
            scan_results: Список результатов сканирования
            
        Returns:
            List[Tuple[Dict, Dict, float]]: Список кортежей (результат1, результат2, схожесть)
        """
        duplicates = []
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=self.console
        ) as progress:
            task = progress.add_task("Поиск дубликатов...", total=len(scan_results))
            
            # Группируем результаты по типу данных
            results_by_type = {}
            for result in scan_results:
                result_type = result['type']
                if result_type not in results_by_type:
                    results_by_type[result_type] = []
                results_by_type[result_type].append(result)
            
            # Ищем дубликаты в каждой группе
            for result_type, type_results in results_by_type.items():
                for i, result1 in enumerate(type_results):
                    content1 = result1['snippet']
                    content_hash1 = self._calculate_content_hash(content1)
                    
                    if content_hash1 in self.content_hashes:
                        for result2 in self.content_hashes[content_hash1]:
                            if result1 != result2:
                                similarity = self._calculate_similarity(content1, result2['snippet'])
                                if similarity >= self.similarity_threshold:
                                    duplicates.append((result1, result2, similarity))
                    else:
                        self.content_hashes[content_hash1] = [result1]
                    
                    progress.advance(task)
                    
        return duplicates

    def clean_duplicates(self, scan_results: List[Dict]) -> List[Dict]:
        """
        Очищает результаты от дубликатов, оставляя только уникальные находки.
        
        Args:
            scan_results: Список результатов сканирования
            
        Returns:
            List[Dict]: Очищенный список результатов
        """
        # Группируем результаты по типу данных
        results_by_type = {}
        for result in scan_results:
            result_type = result['type']
            if result_type not in results_by_type:
                results_by_type[result_type] = []
            results_by_type[result_type].append(result)
        
        cleaned_results = []
        
        # Обрабатываем каждую группу отдельно
        for result_type, type_results in results_by_type.items():
            # Создаем словарь для отслеживания уникальных значений
            seen_values = {}
            
            for result in type_results:
                # Нормализуем значение для сравнения
                normalized_value = self._calculate_content_hash(result['snippet'])
                
                if normalized_value not in seen_values:
                    seen_values[normalized_value] = result
                else:
                    # Если нашли дубликат, выбираем результат с более коротким путем к файлу
                    existing_result = seen_values[normalized_value]
                    if len(result['file']) < len(existing_result['file']):
                        seen_values[normalized_value] = result
            
            cleaned_results.extend(seen_values.values())
        
        # Выводим статистику очистки
        removed_count = len(scan_results) - len(cleaned_results)
        self.console.print(f"[yellow]Удалено {removed_count} дубликатов[/yellow]")
        
        return cleaned_results
        
    def display_duplicates(self, duplicates: List[Tuple[Dict, Dict, float]]):
        """
        Отображает найденные дубликаты в виде таблицы.
        
        Args:
            duplicates: Список найденных дубликатов
        """
        if not duplicates:
            self.console.print("[green]Дубликаты не найдены![/green]")
            return
            
        table = Table(title="Найденные дубликаты")
        table.add_column("Тип", style="cyan")
        table.add_column("Файл 1", style="cyan")
        table.add_column("Строка 1", justify="right", style="green")
        table.add_column("Файл 2", style="cyan")
        table.add_column("Строка 2", justify="right", style="green")
        table.add_column("Схожесть", justify="right", style="yellow")
        
        for result1, result2, similarity in duplicates:
            table.add_row(
                result1['type'],
                result1['file'],
                str(result1['line']),
                result2['file'],
                str(result2['line']),
                f"{similarity:.2%}"
            )
            
        self.console.print(table)

def main():
    """
    Основная функция для поиска дубликатов в сохраненных результатах сканирования.
    """
    console = Console()
    
    # Загружаем результаты сканирования
    try:
        raw_output_path = OUTPUT_DIR / 'raw_scan_results.json'
        with open(raw_output_path, 'r', encoding='utf-8') as f:
            scan_results = json.load(f)
    except FileNotFoundError:
        console.print("[red]Файл с результатами сканирования не найден![/red]")
        return
    except json.JSONDecodeError:
        console.print("[red]Ошибка при чтении файла с результатами![/red]")
        return
        
    # Инициализируем поисковик дубликатов
    finder = DuplicateFinder()
    
    # Очищаем результаты от дубликатов
    cleaned_results = finder.clean_duplicates(scan_results)
    
    # Сохраняем очищенные результаты
    cleaned_output_path = OUTPUT_DIR / 'scan_results.json'
    with open(cleaned_output_path, 'w', encoding='utf-8') as f:
        json.dump(cleaned_results, f, ensure_ascii=False, indent=2)
    console.print(f"[green]Очищенные результаты сохранены в файл {cleaned_output_path}[/green]")

if __name__ == "__main__":
    main() 
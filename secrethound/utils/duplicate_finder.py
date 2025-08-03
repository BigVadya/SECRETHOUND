import json
import hashlib
import re
from pathlib import Path
from typing import Dict, List, Tuple, Set
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from difflib import SequenceMatcher

# Define path to output folder
OUTPUT_DIR = Path('output')

class DuplicateFinder:
    """
    Class for finding duplicates in scan results.
    Analyzes found sensitive data for similarity.
    """
    def __init__(self, similarity_threshold: float = 0.85):
        """
        Initialize duplicate finder.
        
        Args:
            similarity_threshold: Similarity threshold for data (0 to 1)
        """
        self.similarity_threshold = similarity_threshold
        self.console = Console()
        self.content_hashes: Dict[str, List[Dict]] = {}
        
    def _calculate_content_hash(self, content: str) -> str:
        """
        Calculates hash of content after normalization.
        
        Args:
            content: Text to hash
            
        Returns:
            str: MD5 hash of normalized text
        """
        # Normalize text:
        # 1. Convert to lowercase
        # 2. Remove extra spaces
        # 3. Remove special characters
        # 4. Normalize URLs and paths
        normalized = content.lower().strip()
        normalized = re.sub(r'\s+', ' ', normalized)
        normalized = re.sub(r'[^\w\s]', '', normalized)
        normalized = re.sub(r'(https?://)?(www\.)?', '', normalized)
        normalized = re.sub(r'\.internal\.', 'internal', normalized)
        return hashlib.md5(normalized.encode()).hexdigest()
        
    def _calculate_similarity(self, str1: str, str2: str) -> float:
        """
        Calculates similarity between two strings.
        
        Args:
            str1: First string
            str2: Second string
            
        Returns:
            float: Similarity coefficient from 0 to 1
        """
        return SequenceMatcher(None, str1, str2).ratio()
        
    def find_duplicates(self, scan_results: List[Dict]) -> List[Tuple[Dict, Dict, float]]:
        """
        Finds duplicates in scan results.
        
        Args:
            scan_results: List of scan results
            
        Returns:
            List[Tuple[Dict, Dict, float]]: List of tuples (result1, result2, similarity)
        """
        duplicates = []
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=self.console
        ) as progress:
            task = progress.add_task("Searching for duplicates...", total=len(scan_results))
            
            # Group results by data type
            results_by_type = {}
            for result in scan_results:
                result_type = result['type']
                if result_type not in results_by_type:
                    results_by_type[result_type] = []
                results_by_type[result_type].append(result)
            
            # Search for duplicates in each group
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
        Cleans results from duplicates, leaving only unique findings.
        
        Args:
            scan_results: List of scan results
            
        Returns:
            List[Dict]: Cleaned list of results
        """
        # Group results by data type
        results_by_type = {}
        for result in scan_results:
            result_type = result['type']
            if result_type not in results_by_type:
                results_by_type[result_type] = []
            results_by_type[result_type].append(result)
        
        cleaned_results = []
        
        # Process each group separately
        for result_type, type_results in results_by_type.items():
            # Create dictionary for tracking unique values
            seen_values = {}
            
            for result in type_results:
                # Normalize value for comparison
                normalized_value = self._calculate_content_hash(result['snippet'])
                
                if normalized_value not in seen_values:
                    seen_values[normalized_value] = result
                else:
                    # If duplicate found, choose result with shorter file path
                    existing_result = seen_values[normalized_value]
                    if len(result['file']) < len(existing_result['file']):
                        seen_values[normalized_value] = result
            
            cleaned_results.extend(seen_values.values())
        
        # Display cleaning statistics
        removed_count = len(scan_results) - len(cleaned_results)
        self.console.print(f"[yellow]Removed {removed_count} duplicates[/yellow]")
        
        return cleaned_results
        
    def display_duplicates(self, duplicates: List[Tuple[Dict, Dict, float]]):
        """
        Displays found duplicates in table format.
        
        Args:
            duplicates: List of found duplicates
        """
        if not duplicates:
            self.console.print("[green]No duplicates found![/green]")
            return
            
        table = Table(title="Found Duplicates")
        table.add_column("Type", style="cyan")
        table.add_column("File 1", style="cyan")
        table.add_column("Line 1", justify="right", style="green")
        table.add_column("File 2", style="cyan")
        table.add_column("Line 2", justify="right", style="green")
        table.add_column("Similarity", justify="right", style="yellow")
        
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
    Main function for finding duplicates in saved scan results.
    """
    console = Console()
    
    # Load scan results
    try:
        raw_output_path = OUTPUT_DIR / 'raw_scan_results.json'
        with open(raw_output_path, 'r', encoding='utf-8') as f:
            scan_results = json.load(f)
    except FileNotFoundError:
        console.print("[red]Scan results file not found![/red]")
        return
    except json.JSONDecodeError:
        console.print("[red]Error reading results file![/red]")
        return
        
    # Initialize duplicate finder
    finder = DuplicateFinder()
    
    # Clean results from duplicates
    cleaned_results = finder.clean_duplicates(scan_results)
    
    # Save cleaned results
    cleaned_output_path = OUTPUT_DIR / 'scan_results.json'
    with open(cleaned_output_path, 'w', encoding='utf-8') as f:
        json.dump(cleaned_results, f, ensure_ascii=False, indent=2)
    console.print(f"[green]Cleaned results saved to file {cleaned_output_path}[/green]")

if __name__ == "__main__":
    main() 
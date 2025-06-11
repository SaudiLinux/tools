import requests
import argparse
import json
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.progress import Progress

class DomainVulnScanner:
    def __init__(self):
        self.console = Console()
        self.github_api = "https://api.github.com/search/code"
        self.headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "Domain-Vuln-Scanner"
        }

    def search_vulnerabilities(self, domain):
        # كلمات مفتاحية للبحث عن الثغرات المحتملة
        keywords = [
            f"site:{domain} password",
            f"site:{domain} api_key",
            f"site:{domain} secret",
            f"site:{domain} token",
            f"site:{domain} config",
            f"site:{domain} admin",
            f"site:{domain} sql injection",
            f"site:{domain} vulnerability"
        ]

        results = []
        with Progress() as progress:
            task = progress.add_task("[green]جاري البحث عن الثغرات...", total=len(keywords))

            for keyword in keywords:
                try:
                    params = {
                        "q": keyword,
                        "sort": "indexed",
                        "order": "desc"
                    }
                    response = requests.get(self.github_api, headers=self.headers, params=params)
                    if response.status_code == 200:
                        data = response.json()
                        if data.get('total_count', 0) > 0:
                            results.extend([
                                {
                                    'keyword': keyword,
                                    'file': item['name'],
                                    'path': item['path'],
                                    'repo': item['repository']['full_name'],
                                    'url': item['html_url']
                                }
                                for item in data['items'][:5]  # نأخذ أول 5 نتائج لكل كلمة مفتاحية
                            ])
                    progress.update(task, advance=1)
                except Exception as e:
                    self.console.print(f"[red]خطأ في البحث عن {keyword}: {str(e)}[/red]")
                    progress.update(task, advance=1)

        return results

    def display_results(self, results, domain):
        if not results:
            self.console.print(f"\n[yellow]لم يتم العثور على ثغرات محتملة في النطاق {domain}[/yellow]")
            return

        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("نوع الثغرة", style="dim")
        table.add_column("الملف")
        table.add_column("المسار")
        table.add_column("المستودع")
        table.add_column("الرابط")

        for result in results:
            table.add_row(
                result['keyword'].split(':')[1].strip(),
                result['file'],
                result['path'],
                result['repo'],
                result['url']
            )

        self.console.print(f"\n[bold green]نتائج فحص الثغرات لنطاق {domain}:[/bold green]")
        self.console.print(table)

    def save_report(self, results, domain):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"vulnerability_report_{domain}_{timestamp}.json"
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(results, f, ensure_ascii=False, indent=4)
        
        self.console.print(f"\n[bold green]تم حفظ التقرير في الملف: {filename}[/bold green]")

def main():
    parser = argparse.ArgumentParser(description='أداة البحث عن الثغرات في النطاقات')
    parser.add_argument('domain', help='النطاق المراد فحصه')
    args = parser.parse_args()

    scanner = DomainVulnScanner()
    console = Console()

    console.print("\n[bold cyan]===== أداة فحص الثغرات في النطاقات =====[/bold cyan]")
    console.print(f"[bold]النطاق المستهدف:[/bold] {args.domain}\n")

    results = scanner.search_vulnerabilities(args.domain)
    scanner.display_results(results, args.domain)
    scanner.save_report(results, args.domain)

if __name__ == "__main__":
    main()
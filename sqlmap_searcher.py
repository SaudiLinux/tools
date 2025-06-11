import requests
from bs4 import BeautifulSoup
from urllib.parse import quote_plus, urlparse
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
import re
import time
import random

class SQLMapVulnFinder:
    def __init__(self):
        self.console = Console()
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        ]
        self.search_engines = {
            'google': 'https://www.google.com/search?q={}&num=100',
            'bing': 'https://www.bing.com/search?q={}&count=100',
            'duckduckgo': 'https://html.duckduckgo.com/html/?q={}',
            'yandex': 'https://yandex.com/search/?text={}'
        }

    def get_random_user_agent(self):
        return random.choice(self.user_agents)

    def is_potentially_vulnerable(self, url):
        """التحقق من احتمالية وجود ثغرة SQL injection"""
        vulnerable_patterns = [
            'id=',
            'page=',
            'category=',
            'item=',
            'pid=',
            'cat=',
            'product=',
            'article=',
            'news=',
            'user=',
            'view=',
            'profile=',
            'content='
        ]
        
        # تجنب المواقع المعروفة والآمنة
        safe_domains = ['google.com', 'facebook.com', 'twitter.com', 'github.com', 'microsoft.com', 'apple.com']
        parsed_url = urlparse(url)
        if any(domain in parsed_url.netloc for domain in safe_domains):
            return False
            
        return any(pattern in url.lower() for pattern in vulnerable_patterns)

    def extract_urls(self, html_content, engine_name):
        soup = BeautifulSoup(html_content, 'html.parser')
        urls = set()

        if engine_name == 'google':
            for link in soup.find_all('a'):
                href = link.get('href', '')
                if href.startswith('/url?q='):
                    url = href.split('/url?q=')[1].split('&')[0]
                    urls.add(url)
        elif engine_name == 'bing':
            for link in soup.find_all('a', {'class': 'b_attribution'}):
                href = link.get('href', '')
                if href and not href.startswith(('http://go.microsoft.com', 'https://go.microsoft.com')):
                    urls.add(href)
        elif engine_name == 'duckduckgo':
            for link in soup.find_all('a', {'class': 'result__url'}):
                href = link.get('href', '')
                if href:
                    urls.add(href)
        elif engine_name == 'yandex':
            for link in soup.find_all('a', {'class': 'link'}):
                href = link.get('href', '')
                if href and not href.startswith('/search'):
                    urls.add(href)

        return urls

    def search_vulnerable_sites(self, dorks, max_results=50):
        results = []
        total_dorks = len(dorks)

        with Progress() as progress:
            task = progress.add_task("[green]جاري البحث عن المواقع المعرضة للثغرات...", total=total_dorks)

            for dork in dorks:
                for engine_name, engine_url in self.search_engines.items():
                    try:
                        encoded_dork = quote_plus(dork)
                        url = engine_url.format(encoded_dork)
                        headers = {
                            'User-Agent': self.get_random_user_agent(),
                            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                            'Accept-Language': 'en-US,en;q=0.5',
                            'DNT': '1',
                            'Connection': 'keep-alive',
                            'Upgrade-Insecure-Requests': '1'
                        }
                        
                        response = requests.get(url, headers=headers, timeout=10)
                        if response.status_code == 200:
                            urls = self.extract_urls(response.text, engine_name)
                            for url in urls:
                                if self.is_potentially_vulnerable(url):
                                    results.append({
                                        'url': url,
                                        'dork': dork,
                                        'engine': engine_name
                                    })
                                    if len(results) >= max_results:
                                        break
                        
                        # تأخير عشوائي لتجنب الحظر
                        time.sleep(random.uniform(2, 5))
                        
                    except Exception as e:
                        self.console.print(f"[red]خطأ في البحث على {engine_name}: {str(e)}[/red]")
                    
                    if len(results) >= max_results:
                        break
                
                progress.update(task, advance=1)
                if len(results) >= max_results:
                    break

        return results

    def display_results(self, results):
        if not results:
            self.console.print("\n[yellow]لم يتم العثور على مواقع محتملة.[/yellow]")
            return

        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("#", style="dim")
        table.add_column("الرابط")
        table.add_column("محرك البحث")
        table.add_column("الاستعلام المستخدم")

        for i, result in enumerate(results, 1):
            table.add_row(
                str(i),
                result['url'],
                result['engine'],
                result['dork']
            )

        self.console.print("\n[bold green]المواقع المحتمل وجود ثغرات SQL injection فيها:[/bold green]")
        self.console.print(table)
        self.console.print("\n[yellow]تنبيه: هذه النتائج هي مجرد احتمالات وتحتاج إلى تأكيد يدوي.[/yellow]")

def main():
    # قائمة استعلامات البحث المخصصة للعثور على مواقع معرضة
    sql_dorks = [
        'inurl:id= intext:"mysql"',
        'inurl:php?id= intext:"mysql"',
        'inurl:category.php?id=',
        'inurl:product.php?id=',
        'inurl:article.php?id=',
        'inurl:item.php?id=',
        'inurl:view.php?id=',
        'inurl:news.php?id=',
        'inurl:index.php?id=',
        'inurl:main.php?id=',
        'inurl:page.php?pid=',
        'inurl:products.php?cat=',
        'inurl:listing.php?cat=',
        'inurl:gallery.php?id=',
        'inurl:content.php?id='
    ]

    finder = SQLMapVulnFinder()
    console = Console()

    console.print("\n[bold cyan]===== أداة البحث عن ثغرات SQL Injection =====[/bold cyan]")
    console.print("[yellow]تحذير: استخدم هذه الأداة بمسؤولية وفقط على المواقع المصرح لك باختبارها[/yellow]\n")

    results = finder.search_vulnerable_sites(sql_dorks)
    finder.display_results(results)

if __name__ == "__main__":
    main()
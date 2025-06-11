import requests
import json
import sys
from bs4 import BeautifulSoup
from github import Github

def search_vulnerabilities(url):
    vulnerabilities = []
    try:
        # Search in different vulnerability databases
        sources = [
            f'https://www.exploit-db.com/search?q={url}',
            f'https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&query={url}',
            f'https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword={url}'
        ]
        
        for source in sources:
            response = requests.get(source)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                # Extract vulnerability information based on the source
                if 'exploit-db.com' in source:
                    results = soup.find_all('div', class_='exploit_list')
                    for result in results:
                        vulnerabilities.append({
                            'source': 'Exploit-DB',
                            'title': result.get_text().strip(),
                            'link': source
                        })
                elif 'nvd.nist.gov' in source:
                    results = soup.find_all('div', class_='vulnerability-detail')
                    for result in results:
                        vulnerabilities.append({
                            'source': 'NVD',
                            'title': result.get_text().strip(),
                            'link': source
                        })
                elif 'cve.mitre.org' in source:
                    results = soup.find_all('div', class_='cve-detail')
                    for result in results:
                        vulnerabilities.append({
                            'source': 'CVE',
                            'title': result.get_text().strip(),
                            'link': source
                        })
    except Exception as e:
        print(f'Error searching vulnerabilities: {str(e)}')
    
    return vulnerabilities

def save_to_github(vulnerabilities, github_token, repo_name):
    try:
        g = Github(github_token)
        user = g.get_user()
        try:
            repo = user.get_repo(repo_name)
        except:
            repo = user.create_repo(repo_name)
        
        # Create or update vulnerability report
        report_content = json.dumps(vulnerabilities, indent=2, ensure_ascii=False)
        try:
            contents = repo.get_contents('vulnerability_report.json')
            repo.update_file(
                contents.path,
                'Update vulnerability report',
                report_content,
                contents.sha
            )
        except:
            repo.create_file(
                'vulnerability_report.json',
                'Initial vulnerability report',
                report_content
            )
        
        print(f'Successfully saved to GitHub repository: {repo.html_url}')
    except Exception as e:
        print(f'Error saving to GitHub: {str(e)}')

def main():
    if len(sys.argv) != 4:
        print('Usage: python scan1.py <url> <github_token> <repo_name>')
        sys.exit(1)
    
    url = sys.argv[1]
    github_token = sys.argv[2]
    repo_name = sys.argv[3]
    
    print(f'Scanning vulnerabilities for: {url}')
    vulnerabilities = search_vulnerabilities(url)
    
    if vulnerabilities:
        print(f'Found {len(vulnerabilities)} potential vulnerabilities')
        save_to_github(vulnerabilities, github_token, repo_name)
    else:
        print('No vulnerabilities found')

if __name__ == '__main__':
    main()

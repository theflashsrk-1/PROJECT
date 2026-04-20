# GitHub Push — Operation SHATTERED CROWN

## Initial Setup

```bash
git init Red-Range2
cd Red-Range2
cp -r /path/to/extracted/* .
git add .
git commit -m "Operation SHATTERED CROWN - Initial Release"
git remote add origin https://github.com/hacktifytechnologies/Red-Range2.git
git branch -M main
git push -u origin main
```

## Updating

```bash
cd Red-Range2
git add .
git commit -m "Update: <description>"
git push origin main
```

## Cloning for Deployment

```bash
git clone https://github.com/theflashsrk-1/PROJECT.git
cd PROJECT
```

## File Structure

```
Red-Range2/
├── README.md                    # Overview, machine summary, attack steps
├── STORYLINE.md                 # Full red/blue team narrative
├── NETWORK_DIAGRAM.md           # ASCII network diagrams + port matrix
├── AssessmentQuestions.md        # 25 questions (MCQ + static) with answer key
├── GITHUB_PUSH.md               # This file
├── machines/
│   ├── M1-DC02/
│   │   └── setup.ps1            # Domain Controller setup (run first)
│   ├── M2-SRV04-WEB/
│   │   └── setup.ps1            # IIS Web Frontend setup
│   ├── M3-SRV05-API/
│   │   └── setup.ps1            # WinRM API Backend setup
│   ├── M4-SRV06-OPT/
│   │   └── setup.ps1            # Operations Server setup (LSASS vuln)
│   └── M5-SRV07-SQL/
│       └── setup.ps1            # MSSQL Server setup
└── ttps/
    ├── TTP1-password-spray.sh   # Generates spray log artifacts
    ├── TTP2-s4u-delegation.sh   # Generates delegation abuse artifacts
    ├── TTP3-lateral-lsass.sh    # Generates lateral movement + dump artifacts
    ├── TTP4-silver-ticket.sh    # Generates Silver Ticket + privesc artifacts
    └── TTP5-rbcd-domain.sh      # Generates RBCD + DCSync artifacts
```

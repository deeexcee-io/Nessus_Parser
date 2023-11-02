# Nessus_Parser
Collection of my own Simple Python Scripts to Parse a .nessus file making life easier for reporting - txt, docx and xlsx

## Nessus Text Output {PowerShell/cmd)

```powershell
PS C:\Users\gd\Desktop\New folder> python .\nessus-parse.py
Enter the path to your Nessus file: auth-scan.nessus
```

Simple output, gives the IP and lists the findings along with Port Number and Output. If its from a build review (credentialed patch audit) the port will show as 0 on some findings.

![image](https://github.com/deeexcee-io/Nessus_Parser/assets/130473605/d48ad78a-78a9-4571-bf98-8b62600484ff)

## nessus-parse-docx.py

```powershell
PS C:\Users\gd\Desktop\New folder> python .\nessus-parse-docx.py
Enter the path to your Nessus file: auth-scan.nessus
Enter the output Word document file name (e.g., report.docx): report.docx
Word report saved to report.docx
```
Similar to the text output above but in word, nicely laid out

![image](https://github.com/deeexcee-io/Nessus_Parser/assets/130473605/7fc02a90-9a91-42ee-9d45-3862733f2112)

## nessus-parse-excel.py

```powershell
PS C:\Users\gd\Desktop\New folder> python .\nessus-parse-excel.py
Enter the path to your Nessus file: auth-scan.nessus
Enter the output Excel file name (e.g., report.xlsx): report.xlsx
Excel report saved to report.xlsx
```

Quite handy if assessing a large estate which you can filter on etc


![image](https://github.com/deeexcee-io/Nessus_Parser/assets/130473605/681d2f26-f699-435e-a5e6-08feec272fc5)

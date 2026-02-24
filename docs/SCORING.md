# Scoring (0–100)

CoreInspect computes a Security Score by applying:
- Severity-based deductions (Critical/High/Medium/Low/Info)
- Category deduction caps (to avoid score being dominated by repeated findings)

## Example
If a site is missing multiple headers and HSTS:
- The tool subtracts points based on severity and category
- Then caps the deduction within each category

## Grades
- **A**: 90–100
- **B**: 80–89
- **C**: 70–79
- **D**: 50–69
- **F**: 0–49

> The score is a helpful indicator, not a replacement for a full security assessment.
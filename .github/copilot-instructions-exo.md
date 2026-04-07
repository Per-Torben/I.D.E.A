# Exchange Online Specific Instructions

## Connection Patterns
- Always use certificate-based authentication for production scripts
- Store connection logic in reusable functions
- Include proper disconnect/cleanup in scripts

## Common Operations
- Use Get-EXOMailbox instead of Get-Mailbox for better performance, unless specific features of Get-Mailbox are required
- Implement proper filtering to reduce data transfer
- Use batch operations for bulk changes

## Address Book Policy (ABP) Scripts
- Follow the pattern established in existing ABP scripts
- Always validate GAL, OAB, and Address List existence before assignment
- Include rollback procedures for ABP changes

## Calendar Permissions

### CRITICAL: Calendar Folder Path Resolution
**NEVER use hardcoded calendar paths like ":\Calendar" - they are language-dependent and will fail in non-English environments.**

**ALWAYS use this mandatory pattern for calendar folder identification:**
```powershell
# Correct - language-independent calendar folder resolution
$calendarPath = ($mb.SamAccountName) + ":\" + (Get-MailboxFolderStatistics -Identity $mb.SamAccountName -FolderScope Calendar | Select-Object -First 1).Name

# Example usage:
Get-MailboxFolderPermission -Identity $calendarPath
Set-MailboxFolderPermission -Identity $calendarPath -User $user -AccessRights $rights
```

**Why this is required:**
- Calendar folders are named differently in different languages (Calendar, Kalender, Calendrier, etc.)
- This method dynamically discovers the actual calendar folder name
- Prevents script failures in multilingual environments

### Other Calendar Permission Guidelines
- Use proper permission levels (Owner, Editor, Reviewer, etc.)
- Validate user existence before granting permissions
- Log all permission changes for audit purposes 

#!/bin/bash

check_ftp() {
   local target=$1
   local port=$2

   echo "Starting FTP anonymous login check on port $port..."
   echo "--- FTP Anonymous Login (port $port) ---" | tee -a report/findings.txt

   ftp_output=$(curl -sS --connect-timeout 5 --ftp-pasv \
      -u "anonymous:anonymous" \
      "ftp://$target:$port/" 2>&1)

   ftp_status=$?

   echo "$ftp_output" | tee -a report/findings.txt

   if [[ "$ftp_status" -eq 0 ]]; then

      echo "FTP anonymous access appears to be allowed." | tee -a report/findings.txt
      echo "Risk: Anonymous FTP access may expose files to unauthenticated users." | tee -a report/findings.txt
      echo "Recommendation: Disable anonymous FTP access or restrict its permissions." | tee -a report/findings.txt

      echo "" | tee -a report/findings.txt
      echo "--- FTP Anonymous File Listing (port $port) ---" | tee -a report/findings.txt

      if [[ -n "$ftp_output" ]]; then

         echo "Files and directories accessible through anonymous FTP:" | tee -a report/findings.txt
         echo "$ftp_output" | tee -a report/findings.txt
         echo "Anonymous FTP directory listing was successfully retrieved." | tee -a report/findings.txt

      else

         echo "Anonymous FTP access was confirmed, but no directory contents were returned." | tee -a report/findings.txt
         echo "The FTP service accepted the anonymous request, but the directory listing was empty or unavailable." | tee -a report/findings.txt

      fi

   else

      echo "Anonymous FTP access was not confirmed." | tee -a report/findings.txt

   fi
}


check_ssh() {
   local target=$1
   local port=$2

   echo "Extracting SSH banner..."
   echo "--- SSH Banner ---" | tee -a report/findings.txt

   ssh_output=$(nc -w 2 "$target" "$port" </dev/null 2>&1)

   echo "$ssh_output" | head -n 3 | tee -a report/findings.txt

   if echo "$ssh_output" | grep -q "SSH-"; then
      echo "SSH service and banner were successfully identified." | tee -a report/findings.txt
      echo "Risk: Exposed SSH banners can reveal the exact OS and software version to potential attackers." | tee -a report/findings.txt
      echo "Recommendation: Consider hiding or modifying the SSH banner configuration to minimize information disclosure." | tee -a report/findings.txt
   fi
}


check_telnet() {
   local target=$1
   local port=$2

   echo "Extracting Telnet banner..."
   echo "--- Telnet Banner ---" | tee -a report/findings.txt

   telnet_output=$(echo "" | nc -w 2 "$target" "$port" 2>&1)

   clean_output=$(echo "$telnet_output" | tr -cd '\11\12\15\40-\176')

   echo "$clean_output" | head -n 5 | tee -a report/findings.txt

   echo "Telnet service detected on port $port." | tee -a report/findings.txt
   echo "Risk: Telnet communication is not strongly encrypted." | tee -a report/findings.txt
   echo "Recommendation: Replace Telnet with SSH where possible." | tee -a report/findings.txt
}


credential_audit() {
   local target=$1

   echo ""
   echo "======================================"
   echo "Credential Auditing"
   echo "======================================"

   if ! command -v hydra &> /dev/null; then
      echo "Hydra is not installed. Credential auditing skipped."
      return
   fi

   if [[ ! -s report/smtp_users.txt ]]; then
      echo "No SMTP usernames were found. Credential auditing skipped."
      return
   fi

   echo ""
   echo "Discovered SMTP usernames:"
   echo "--------------------------------------"
   nl -w2 -s'. ' report/smtp_users.txt
   echo "--------------------------------------"

   echo ""
   echo "Choose username mode:"
   echo "1) Test all discovered users"
   echo "2) Test one specific user"
   echo "3) Skip credential auditing"
   echo ""

   while true; do
      read -r -p "Enter your choice [1-3]: " user_choice < /dev/tty

      case "$user_choice" in
         1)
            selected_users="report/smtp_users.txt"
            hydra_user_option="-L"
            break
            ;;

         2)
            read -r -p "Enter username: " selected_user < /dev/tty

            if grep -Fxq "$selected_user" report/smtp_users.txt; then
               selected_users="$selected_user"
               hydra_user_option="-l"
               break
            else
               echo "Username '$selected_user' was not found in the discovered users list."
            fi
            ;;

         3)
            echo "Credential auditing skipped."
            return
            ;;

         *)
            echo "Invalid choice. Please enter 1, 2, or 3."
            ;;
      esac
   done

   echo ""
   echo "Choose a wordlist."
   echo "Example: /usr/share/wordlists/rockyou.txt"
   echo ""

   while true; do
      read -r -p "Wordlist path: " wordlist < /dev/tty

      if [[ -f "$wordlist" ]]; then
         break
      else
         echo "Wordlist not found: $wordlist"
         echo "Please enter a valid wordlist path."
      fi
   done

   echo ""
   echo "Choose authentication service:"
   echo "1) SSH"
   echo "2) FTP"
   echo "3) Skip"
   echo ""

   while true; do
      read -r -p "Enter your choice [1-3]: " service_choice < /dev/tty

      case "$service_choice" in
         1)
            service="ssh"
            break
            ;;

         2)
            service="ftp"
            break
            ;;

         3)
            echo "Credential auditing skipped."
            return
            ;;

         *)
            echo "Invalid choice. Please enter 1, 2, or 3."
            ;;
      esac
   done

   echo ""
   echo "Starting Hydra credential audit..."
   echo "Target: $target"
   echo "Service: $service"
   echo ""

   > report/hydra_raw.txt
   > report/credentials.txt

   if [[ "$hydra_user_option" == "-L" ]]; then

      hydra -t 4 -I -L "$selected_users" -P "$wordlist" \
         "$service://$target" 2>&1 | tee report/hydra_raw.txt

   else

      hydra -t 4 -V -I -F -l "$selected_users" -P "$wordlist" \
         "$service://$target" 2>&1 | tee report/hydra_raw.txt

   fi

   hydra_output=$(cat report/hydra_raw.txt)

   echo ""
   echo "--- Successful Credentials ---" | tee -a report/findings.txt

   successful_creds=$(echo "$hydra_output" | grep -iE "login: .*password: ")

   if [[ -n "$successful_creds" ]]; then

      echo "$successful_creds" | while IFS= read -r line
      do
         username=$(echo "$line" | sed -n 's/.*login: \([^ ]*\).*/\1/p')
         password=$(echo "$line" | sed -n 's/.*password: \(.*\)/\1/p')

         if [[ -n "$username" && -n "$password" ]]; then
            echo "$username:$password" >> report/credentials.txt
            echo "$username:$password" | tee -a report/findings.txt
         fi
      done

      echo "Risk: Valid credentials were identified through credential auditing." | tee -a report/findings.txt
      echo "Recommendation: Change weak credentials and enforce strong password policies." | tee -a report/findings.txt
      echo "Successful credentials were saved to report/credentials.txt"

   else

      echo "No valid credentials were identified." | tee -a report/findings.txt

   fi
}


check_smtp() {
   local target=$1

   echo "Starting SMTP checks..."

   echo "--- SMTP User Enumeration ---" | tee -a report/findings.txt

   echo "SMTP User Enumeration Tool: smtp-user-enum v1.2" | tee -a report/findings.txt
   echo "Testing whether the SMTP service discloses valid usernames." | tee -a report/findings.txt

   if ! command -v smtp-user-enum &> /dev/null; then
      echo "smtp-user-enum is not installed." | tee -a report/findings.txt
      return
   fi

   userlist="wordlists/top-usernames-shortlist.txt"

   if [[ ! -f "$userlist" ]]; then
      echo "Username wordlist not found: $userlist" | tee -a report/findings.txt
      return
   fi

   echo "Username wordlist: $userlist" | tee -a report/findings.txt
   echo "Starting SMTP username enumeration..." | tee -a report/findings.txt

   smtp_output=$(smtp-user-enum -M VRFY -U "$userlist" -t "$target" 2>&1)

   echo "$smtp_output" > report/smtp_enum_raw.txt

   echo "--- SMTP Enumeration Result ---" | tee -a report/findings.txt
   echo "$smtp_output" | tee -a report/findings.txt

   echo "$smtp_output" |
   grep " exists" |
   awk '{print $2}' |
   sort -u > report/smtp_users.txt

   if [[ -s report/smtp_users.txt ]]; then

      echo "" | tee -a report/findings.txt
      echo "Valid SMTP users were identified:" | tee -a report/findings.txt

      cat report/smtp_users.txt | tee -a report/findings.txt

      echo "" | tee -a report/findings.txt
      echo "Total users found: $(wc -l < report/smtp_users.txt)" | tee -a report/findings.txt

      if grep -Fxq "root" report/smtp_users.txt; then
         echo "root user was identified." | tee -a report/findings.txt
      else
         echo "root user was not identified." | tee -a report/findings.txt
      fi

      echo "Risk: SMTP username enumeration may disclose valid system accounts." | tee -a report/findings.txt
      echo "Recommendation: Disable or restrict SMTP VRFY/EXPN functionality where possible." | tee -a report/findings.txt

      credential_audit "$target"

   else

      echo "No valid SMTP usernames were identified." | tee -a report/findings.txt
      echo "SMTP enumeration completed without discovering users." | tee -a report/findings.txt

   fi
}


check_dns() {
   local target=$1

   echo "Starting DNS information check..."
   echo "--- DNS Information ---" | tee -a report/findings.txt

   dns_output=$(dig @"$target" SOA 2>&1)

   if echo "$dns_output" | grep -q "status: NOERROR"; then

      echo "$dns_output" | grep -E "status:|ANSWER:|AUTHORITY:" |
      tee -a report/findings.txt

      echo "DNS service responded to SOA queries." | tee -a report/findings.txt
      echo "Note: DNS zone transfer was not tested because a specific DNS zone name was not identified automatically." |
      tee -a report/findings.txt

   else

      echo "DNS SOA information could not be retrieved." | tee -a report/findings.txt

   fi
}


check_http() {
   local target=$1
   local port=$2

   echo "Starting HTTP enumeration..."
   echo "--- HTTP Headers (port $port) ---" | tee -a report/findings.txt

   base_url="http://$target:$port"

   http_headers=$(curl -s -I --connect-timeout 5 "$base_url/")

   echo "$http_headers" | tee -a report/findings.txt

   if echo "$http_headers" | grep -qi "Server:"; then
      echo "HTTP server information was disclosed in response headers." | tee -a report/findings.txt
      echo "Risk: Server information can help reconnaissance." | tee -a report/findings.txt
      echo "Recommendation: Minimize unnecessary server/version information." | tee -a report/findings.txt
   fi

   echo "" | tee -a report/findings.txt
   echo "--- robots.txt (port $port) ---" | tee -a report/findings.txt

   robots_status=$(curl -s -o /dev/null -w "%{http_code}" \
      --connect-timeout 5 \
      "$base_url/robots.txt")

   if [[ "$robots_status" == "200" ]]; then

      curl -s --connect-timeout 5 "$base_url/robots.txt" |
      tee -a report/findings.txt

   else

      echo "robots.txt -> HTTP $robots_status" | tee -a report/findings.txt

   fi

   echo "" | tee -a report/findings.txt
   echo "--- Common Web Paths (port $port) ---" | tee -a report/findings.txt

   paths=(
      "/admin"
      "/login"
      "/uploads"
      "/backup"
      "/test"
      "/server-status"
      "/phpinfo.php"
      "/robots.txt"
   )

   for path in "${paths[@]}"
   do
      response=$(curl -s -o /dev/null -w "%{http_code}" \
         --connect-timeout 5 \
         "$base_url$path")

      case "$response" in

         200)

            echo "[+] $path -> 200 OK" | tee -a report/findings.txt

            content=$(curl -s --connect-timeout 5 "$base_url$path")

            if echo "$content" | grep -qiE "Index of /|Directory listing"; then

               echo "    [!] Directory listing detected." | tee -a report/findings.txt
               echo "Risk: Directory listings may expose files and application structure." | tee -a report/findings.txt
               echo "Recommendation: Disable directory listing where it is not required." | tee -a report/findings.txt

            fi

            if [[ "$path" == "/phpinfo.php" ]]; then

               echo "    [!] PHP information page detected." | tee -a report/findings.txt
               echo "Risk: PHP information pages may disclose sensitive server and application configuration." | tee -a report/findings.txt
               echo "Recommendation: Remove phpinfo.php from production systems or restrict access." | tee -a report/findings.txt

            fi

            ;;

         301|302)

            echo "[+] $path -> $response Redirect" | tee -a report/findings.txt
            ;;

         403)

            echo "[!] $path -> 403 Forbidden" | tee -a report/findings.txt
            ;;

         404)

            echo "[-] $path -> 404 Not Found" | tee -a report/findings.txt
            ;;

         *)

            echo "[?] $path -> HTTP $response" | tee -a report/findings.txt
            ;;

      esac

   done

   echo "" | tee -a report/findings.txt
   echo "--- Directory Listing Check (port $port) ---" | tee -a report/findings.txt

   root_content=$(curl -s --connect-timeout 5 "$base_url/")

   if echo "$root_content" | grep -qiE "Index of /|Directory listing"; then

      echo "[!] Directory listing appears to be enabled." | tee -a report/findings.txt
      echo "Risk: Directory listings may expose files and application structure." | tee -a report/findings.txt
      echo "Recommendation: Disable directory listing where it is not required." | tee -a report/findings.txt

   else

      echo "Directory listing was not detected." | tee -a report/findings.txt

   fi
}


check_smb() {
   local target=$1

   echo "Starting SMB enumeration..."
   echo "--- SMB Anonymous Share Enumeration ---" | tee -a report/findings.txt

   smb_output=$(smbclient -L "$target" -N 2>&1)

   echo "$smb_output" | tee -a report/findings.txt

   if echo "$smb_output" | grep -qi "Anonymous login successful"; then

      echo "Anonymous SMB access is allowed." | tee -a report/findings.txt
      echo "Risk: Anonymous access may expose shared resources." | tee -a report/findings.txt
      echo "Recommendation: Disable anonymous SMB access and restrict share permissions." | tee -a report/findings.txt

      echo "" | tee -a report/findings.txt
      echo "--- SMB Accessible Share Enumeration ---" | tee -a report/findings.txt
      echo "Testing discovered disk shares for anonymous access..." | tee -a report/findings.txt

      echo "$smb_output" |
      awk '$2 == "Disk" {print $1}' |
      grep -vE '^(IPC\$|ADMIN\$|print\$)$' |
      sort -u > report/smb_shares.txt

      if [[ -s report/smb_shares.txt ]]; then

         echo "Discovered SMB disk shares:" | tee -a report/findings.txt
         cat report/smb_shares.txt | tee -a report/findings.txt

         echo "" | tee -a report/findings.txt

         while IFS= read -r share
         do
            [[ -z "$share" ]] && continue

            echo "--- Share: $share ---" | tee -a report/findings.txt

            share_output=$(smbclient "//$target/$share" -N -c 'ls' 2>&1)

            echo "$share_output" | tee -a report/findings.txt

            if echo "$share_output" | grep -qiE "NT_STATUS_ACCESS_DENIED|NT_STATUS_LOGON_FAILURE|session setup failed"; then

               echo "Anonymous access to share '$share' was not permitted." | tee -a report/findings.txt

            elif echo "$share_output" | grep -qiE "blocks available|blocks of size"; then

               echo "Anonymous access to share '$share' was confirmed." | tee -a report/findings.txt
               echo "Accessible resources were listed for share '$share'." | tee -a report/findings.txt

            else

               echo "Share '$share' responded to the anonymous access attempt." | tee -a report/findings.txt

            fi

         done < report/smb_shares.txt

         echo "" | tee -a report/findings.txt
         echo "Risk: Anonymous SMB shares may expose files or directories to unauthenticated users." | tee -a report/findings.txt
         echo "Recommendation: Disable guest access and restrict share permissions to authorized users." | tee -a report/findings.txt

      else

         echo "No accessible SMB disk shares were identified." | tee -a report/findings.txt

      fi

   else

      echo "Anonymous SMB login was not confirmed." | tee -a report/findings.txt

   fi
}


Target=$1


if [[ "$1" == "-h" || "$1" == "--help" ]]; then

    echo "=================================================="
    echo "   Automated Security Assessment Tool (Secscan)  "
    echo "=================================================="
    echo "Usage:"
    echo "  ./SecurityScan.sh <target_ip>   Start the security scan on target"
    echo "  ./SecurityScan.sh --help        Show this help message"
    echo "  ./SecurityScan.sh --version     Show tool version information"
    echo "=================================================="

    exit 0
fi


if [[ "$1" == "-v" || "$1" == "--version" ]]; then

    echo "PentestTool - Version 1.0.0 (Stable)"
    echo "Developed for Instant Software Solutions Project Brief."

    exit 0
fi


if [[ -z "$Target" ]]; then

   echo "Usage: ./SecurityScan.sh <target>"
   exit 1

fi


for tool in nmap ping arp curl nc dig smbclient
do

   if ! command -v "$tool" &> /dev/null; then

      echo "warning $tool is not installed. Please install it before running the script."
      exit 1

   fi

done


if ! ping -c 1 "$Target" &> /dev/null; then

   echo "Target is unreachable"
   exit 1

fi


echo "Target $Target is online and ready for scanning"
echo "======================================"
echo "Gathering Target Information"
echo "====================================="


mkdir -p report


> report/findings.txt
> report/summary.txt
> report/open_ports.txt
> report/recon.txt
> report/scan.txt
> report/smtp_users.txt
> report/smtp_enum_raw.txt
> report/credentials.txt
> report/hydra_raw.txt
> report/smb_shares.txt


echo "Target: $Target" | tee report/summary.txt
echo "Scan Date: $(date)" | tee -a report/summary.txt
echo "" | tee -a report/summary.txt


echo "--- Basic Network Information ---" | tee report/recon.txt
echo "IP Address: $Target" | tee -a report/recon.txt
echo "Hostname Information:" | tee -a report/recon.txt
getent hosts "$Target" | tee -a report/recon.txt
echo "ARP Information:" | tee -a report/recon.txt
arp -an | grep "$Target" | tee -a report/recon.txt
echo ""


echo "Starting Nmap Scan..."
echo "====================="


nmap -sV -p- "$Target" | tee report/scan.txt


echo ""


echo "Required Services"
echo "================="


grep -E "^[0-9]+/tcp[[:space:]]+open[[:space:]]+(ftp|ssh|telnet|smtp|domain|http|netbios-ssn|microsoft-ds)" report/scan.txt |
awk '{print "Port: "$1"  Service: "$3"  Version: "$4" "$5" "$6}' |
tee report/open_ports.txt


echo "" >> report/summary.txt
echo "Open Ports:" >> report/summary.txt
cat report/open_ports.txt >> report/summary.txt


smb_checked=0


while read -r port service
do

   echo ""
   echo "$service detected on port $port"


   if [[ "$service" == "netbios-ssn" || "$service" == "microsoft-ds" ]]; then

      if [[ "$smb_checked" -eq 1 ]]; then
         continue
      fi

      smb_checked=1
      check_smb "$Target"


   elif [[ "$service" == "smtp" ]]; then

      check_smtp "$Target"


   elif [[ "$service" == "domain" ]]; then

      check_dns "$Target"


   elif [[ "$service" == "ftp" ]]; then

      check_ftp "$Target" "$port"


   elif [[ "$service" == "ssh" ]]; then

      check_ssh "$Target" "$port"


   elif [[ "$service" == "telnet" ]]; then

      check_telnet "$Target" "$port"


   elif [[ "$service" == "http" ]]; then

      check_http "$Target" "$port"

   fi

done < <(

   grep -E "^[0-9]+/tcp[[:space:]]+open[[:space:]]+(ftp|ssh|telnet|smtp|domain|http|netbios-ssn|microsoft-ds)" report/scan.txt |
   awk '{print $1, $3}' |
   sed 's/\/tcp//'

)


echo ""
echo "======================================"
echo "Security Assessment Completed"
echo "======================================"


echo "Security Assessment Summary" > report/summary.txt
echo "================================" >> report/summary.txt
echo "" >> report/summary.txt

echo "Target: $Target" >> report/summary.txt
echo "Scan Date: $(date)" >> report/summary.txt
echo "" >> report/summary.txt

echo "Open Ports:" >> report/summary.txt
cat report/open_ports.txt >> report/summary.txt
echo "" >> report/summary.txt

echo "Findings:" >> report/summary.txt
cat report/findings.txt >> report/summary.txt


echo ""
echo "Reports generated:"
echo "report/recon.txt"
echo "report/scan.txt"
echo "report/open_ports.txt"
echo "report/findings.txt"
echo "report/summary.txt"
echo "report/smtp_enum_raw.txt"
echo "report/smtp_users.txt"
echo "report/hydra_raw.txt"
echo "report/credentials.txt"
echo "report/smb_shares.txt"


html_report="report/report.html"


echo "<html>" > "$html_report"

echo "<head>" >> "$html_report"
echo "<meta charset=\"UTF-8\">" >> "$html_report"
echo "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">" >> "$html_report"
echo "<title>Security Assessment Report</title>" >> "$html_report"


echo "<style>" >> "$html_report"

echo "body { font-family: Arial, sans-serif; margin: 30px; background-color: #f4f6f9; color: #222; line-height: 1.6; }" >> "$html_report"

echo "h1 { color: #b30000; border-bottom: 3px solid #b30000; padding-bottom: 10px; margin-bottom: 25px; }" >> "$html_report"

echo "h2 { margin-top: 25px; color: #333; border-left: 5px solid #b30000; padding-left: 10px; }" >> "$html_report"

echo ".section { background: white; padding: 20px; margin-bottom: 20px; border-radius: 8px; box-shadow: 0 2px 6px rgba(0,0,0,0.08); }" >> "$html_report"

echo ".finding { background: #ffffff; border-left: 5px solid #b30000; padding: 15px; margin: 15px 0; border-radius: 6px; box-shadow: 0 2px 5px rgba(0,0,0,0.08); }" >> "$html_report"

echo ".finding-title { font-size: 18px; font-weight: bold; margin-bottom: 10px; color: #b30000; }" >> "$html_report"

echo ".finding-content { background: #fafafa; padding: 12px; border-radius: 5px; white-space: pre-wrap; overflow-x: auto; color: #222; }" >> "$html_report"

echo ".risk { color: #b71c1c; font-weight: bold; background: #ffebee; border-left: 4px solid #c62828; padding: 8px 10px; border-radius: 4px; margin: 8px 0; }" >> "$html_report"

echo ".recommendation { color: #0d47a1; font-weight: bold; background: #e3f2fd; border-left: 4px solid #1565c0; padding: 8px 10px; border-radius: 4px; margin: 8px 0; }" >> "$html_report"

echo ".success { color: #1b5e20; font-weight: bold; background: #e8f5e9; border-left: 4px solid #2e7d32; padding: 8px 10px; border-radius: 4px; margin: 8px 0; }" >> "$html_report"

echo ".warning { color: #e65100; font-weight: bold; }" >> "$html_report"

echo ".info { color: #1565c0; font-weight: bold; }" >> "$html_report"

echo ".normal { color: #222; }" >> "$html_report"

echo "pre { background: #f1f3f5; padding: 15px; border-radius: 6px; overflow-x: auto; white-space: pre-wrap; color: #222; }" >> "$html_report"

echo "</style>" >> "$html_report"


echo "</head>" >> "$html_report"
echo "<body>" >> "$html_report"


echo "<h1>Security Assessment Report</h1>" >> "$html_report"
echo "<h2>Scan Information</h2>" >> "$html_report"


echo "<div class=\"section\">" >> "$html_report"
echo "Target: $Target<br>" >> "$html_report"
echo "Scan Date: $(date)" >> "$html_report"
echo "</div>" >> "$html_report"


echo "<h2>Open Ports</h2>" >> "$html_report"
echo "<div class=\"section\">" >> "$html_report"
echo "<pre>" >> "$html_report"

cat report/open_ports.txt >> "$html_report"

echo "</pre>" >> "$html_report"
echo "</div>" >> "$html_report"


echo "<h2>Detailed Findings</h2>" >> "$html_report"
echo "<div class=\"section\">" >> "$html_report"


current_title=""


while IFS= read -r line
do

   if [[ "$line" == ---*--- ]]; then

      if [[ -n "$current_title" ]]; then
         echo "</div>" >> "$html_report"
         echo "</div>" >> "$html_report"
      fi

      current_title="${line#--- }"
      current_title="${current_title% ---}"

      echo "<div class=\"finding\">" >> "$html_report"
      echo "<div class=\"finding-title\">$current_title</div>" >> "$html_report"
      echo "<div class=\"finding-content\">" >> "$html_report"


   else

      if [[ -n "$current_title" ]]; then

         if [[ "$current_title" == "Successful Credentials" ]]; then

            if [[ "$line" == "Risk:"* ]]; then

               risk_text="${line#Risk: }"
               echo "<div class=\"risk\">Risk: $risk_text</div>" >> "$html_report"

            elif [[ "$line" == "Recommendation:"* ]]; then

               recommendation_text="${line#Recommendation: }"
               echo "<div class=\"recommendation\">Recommendation: $recommendation_text</div>" >> "$html_report"

            elif [[ "$line" =~ ^([[:alnum:]_.-]+):([^[:space:]].*)$ ]]; then

               username="${BASH_REMATCH[1]}"
               password="${BASH_REMATCH[2]}"

               masked_password=$(printf '%*s' "${#password}" '' | tr ' ' '*')

               echo "<div class=\"success\">$username: $masked_password</div>" >> "$html_report"

            elif [[ -n "$line" ]]; then

               echo "<div class=\"normal\">$line</div>" >> "$html_report"

            fi

         else

            if [[ "$line" == "Risk:"* ]]; then

               risk_text="${line#Risk: }"
               echo "<div class=\"risk\">Risk: $risk_text</div>" >> "$html_report"

            elif [[ "$line" == "Recommendation:"* ]]; then

               recommendation_text="${line#Recommendation: }"
               echo "<div class=\"recommendation\">Recommendation: $recommendation_text</div>" >> "$html_report"

            elif [[ "$line" == *"successfully"* || "$line" == *"confirmed"* || "$line" == *"allowed"* ]]; then

               echo "<div class=\"success\">$line</div>" >> "$html_report"

            elif [[ "$line" == "[!]"* || "$line" == "    [!]"* ]]; then

               echo "<div class=\"warning\">$line</div>" >> "$html_report"

            elif [[ "$line" == "[+]"* ]]; then

               echo "<div class=\"success\">$line</div>" >> "$html_report"

            elif [[ "$line" == "[-]"* ]]; then

               echo "<div class=\"info\">$line</div>" >> "$html_report"

            elif [[ "$line" == "[?]"* ]]; then

               echo "<div class=\"info\">$line</div>" >> "$html_report"

            elif [[ -n "$line" ]]; then

               echo "<div class=\"normal\">$line</div>" >> "$html_report"

            else

               echo "<br>" >> "$html_report"

            fi

         fi

      fi

   fi

done < report/findings.txt


if [[ -n "$current_title" ]]; then

   echo "</div>" >> "$html_report"
   echo "</div>" >> "$html_report"

fi


echo "</div>" >> "$html_report"
echo "</body>" >> "$html_report"
echo "</html>" >> "$html_report"


echo "[+] HTML Report generated successfully at: $html_report"

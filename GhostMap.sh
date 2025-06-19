#!/bin/bash

#if pipefail
set -euo pipefail

BOX=$1
TARGET=$(getent hosts "$BOX" | awk '{ print $1 }')

if [[ -z "$TARGET" ]]; then
  echo -e "\e[1;31m[!] Could not resolve $BOX to an IP.\e[0m"
  exit 1
fi

OUTFILE="${BOX}-scan"

echo -e "\e[1;36m[*] Running RustScan on $BOX ($TARGET)...\e[0m"
rustscan -a "$TARGET" --ulimit 5000 -- -sS -Pn -n --open -oX "${OUTFILE}.xml"

cp "${OUTFILE}.xml" "${OUTFILE}.json"
echo -e "\e[1;36m[*] Scan saved to ${OUTFILE}.json (usable with jq)\e[0m"

WEB_PORTS=$(grep 'port protocol="tcp"' "${OUTFILE}.xml" | grep -oP 'portid="\K[0-9]+' | grep -E '80|443|8000|8080|8443|8888|5000|9000|3000|7001|8181' | sort -u)

if [[ -z "$WEB_PORTS" ]]; then
  echo -e "\e[1;33m[*] No common web ports found. Exiting.\e[0m"
  exit 0
fi

echo -e "\e[1;36m[*] Web ports found:\e[0m $WEB_PORTS"

for PORT in $WEB_PORTS; do
  echo -e "\n\e[1;34m[>] Probing https://$TARGET:$PORT\e[0m"

  HEADER=$(curl -I -k --max-time 3 "https://$TARGET:$PORT" 2>/dev/null | grep -i "Server")
  echo "$HEADER"

  BACKEND_ERR=$(curl -k --max-time 4 "https://$TARGET:$PORT/doesnotexist" 2>/dev/null | grep -Ei "tomcat|whitelabel|express|jetty|flask|weblogic|wildfly|error|stack")

  RESPONSE=$(curl -k --max-time 3 -s -o /dev/null -w "%{http_code}" "https://$TARGET:$PORT/;foo=bar/")
  echo "[*] Path smuggling probe (/;foo=bar/): HTTP $RESPONSE"

  # 🟢 Detect front-end proxy
  PROXY=""
  if echo "$HEADER" | grep -iq "nginx"; then
    PROXY="NGINX"
    echo -e "\e[1;32m[*] Frontend detected:\e[0m NGINX"
  elif echo "$HEADER" | grep -iq "apache"; then
    PROXY="Apache"
    echo -e "\e[1;32m[*] Frontend detected:\e[0m Apache"
  elif echo "$HEADER" | grep -iq "microsoft" || echo "$HEADER" | grep -iq "iis"; then
    PROXY="IIS"
    echo -e "\e[1;32m[*] Frontend detected:\e[0m IIS"
  fi

  # 🔴 Detect backend technology
  BACKEND=""
  if echo "$BACKEND_ERR" | grep -iq "tomcat"; then
    BACKEND="Tomcat"
  elif echo "$BACKEND_ERR" | grep -iq "jetty"; then
    BACKEND="Jetty"
  elif echo "$BACKEND_ERR" | grep -iq "whitelabel"; then
    BACKEND="Spring Boot"
  elif echo "$BACKEND_ERR" | grep -iq "flask"; then
    BACKEND="Flask"
  elif echo "$BACKEND_ERR" | grep -iq "weblogic"; then
    BACKEND="WebLogic"
  elif echo "$BACKEND_ERR" | grep -iq "wildfly"; then
    BACKEND="WildFly"
  fi

  # ✅ Check dangerous combos
  if [[ "$PROXY" == "NGINX" && "$BACKEND" == "Tomcat" ]]; then
    echo -e "\e[1;41m[!!] NGINX → Tomcat detected — CLASSIC path smuggling combo!\e[0m"
  elif [[ "$PROXY" == "NGINX" && "$BACKEND" == "Jetty" ]]; then
    echo -e "\e[1;41m[!!] NGINX → Jetty detected — path param dropping is likely!\e[0m"
  elif [[ "$PROXY" == "NGINX" && "$BACKEND" == "Flask" ]]; then
    echo -e "\e[1;41m[!!] NGINX → Flask detected — path-sensitive backend!\e[0m"
  elif [[ "$PROXY" == "Apache" && "$BACKEND" == "Tomcat" ]]; then
    echo -e "\e[1;41m[!!] Apache → Tomcat — often misconfigured!\e[0m"
  elif [[ "$PROXY" == "IIS" && ( "$BACKEND" == "WebLogic" || "$BACKEND" == "WildFly" ) ]]; then
    echo -e "\e[1;41m[!!] IIS → $BACKEND — potential path collapsing!\e[0m"
  fi
done

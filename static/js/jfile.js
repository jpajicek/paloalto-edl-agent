function myFunction() {
  var elmnt = document.getElementById("scroll-to");
  elmnt.scrollIntoView();
}

function validate_isIPaddress() {
  var ipformat = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  var ipaddress_add = document.forms["threat_whitelist"]["whitelist_add"].value;
  var ipaddress_remove = document.forms["threat_whitelist"]["whitelist_remove"].value;
  
  if( ipaddress_add && ipaddress_add.match(ipformat) || ipaddress_remove && ipaddress_remove.match(ipformat) ) {
    return true;
  } else {
    alert("You have entered an invalid IP address!");
    return false;
  }
} 

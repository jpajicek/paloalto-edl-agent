function myFunction() {
  var elmnt = document.getElementById("scroll-to");
  elmnt.scrollIntoView();
}

function validate_isIPaddress() {
  var ipformat = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  var prefixformat = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\/([0-9]|[1-2][0-9]|3[0-2]))$/;
  var ipaddress_add = document.forms["threat_whitelist"]["whitelist_add"].value;
  var ipaddress_remove = document.forms["threat_whitelist"]["whitelist_remove"].value;
  var prefix_add = document.forms["threat_whitelist"]["whitelist_prefix_add"].value;
  var prefix_remove = document.forms["threat_whitelist"]["whitelist_prefix_remove"].value;
  
  if ( ipaddress_add || ipaddress_remove ) {
   if( ipaddress_add.match(ipformat) || ipaddress_remove.match(ipformat) ) {
    return true;
   } else {
    alert("You have entered an invalid IP address!");
    return false;
   }
  }

  if ( prefix_add || prefix_remove ) {
   if( prefix_add.match(prefixformat) || prefix_remove.match(prefixformat) ) {
     return true;
   } else {
     alert("You have entered an invalid IP prefix!");
     return false;
   }
  }

} 

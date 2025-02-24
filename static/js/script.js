function disableButton(){
    document.getElementById("submitBTN").disabled = true;
}

function Get_Cookie(name) {
    var start = document.cookie.indexOf(name + "=");
    if (start === -1) return null; 
    var len = start + name.length + 1;
    var end = document.cookie.indexOf(";", len);
    if (end === -1) end = document.cookie.length;
    return decodeURIComponent(document.cookie.substring(len, end));
}

function cookiecheck() {
    var cookietest = Get_Cookie('access_token_cookie'); 

    if (cookietest == null || cookietest.trim() === "") {
        document.getElementById("nocookie").style.display = "block";
        document.getElementById("cookie").style.display = "none";
    } else {
        document.getElementById("nocookie").style.display = "none";
        document.getElementById("cookie").style.display = "block";
    }
}
document.addEventListener("DOMContentLoaded", cookiecheck());
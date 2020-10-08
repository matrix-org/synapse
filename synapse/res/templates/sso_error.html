<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>SSO error</title>
</head>
<body>
{# If an error of unauthorised is returned it means we have actively rejected their login #}
{% if error == "unauthorised" %}
    <p>You are not allowed to log in here.</p>
{% else %}
    <p>
        There was an error during authentication:
    </p>
    <div id="errormsg" style="margin:20px 80px">{{ error_description | e }}</div>
    <p>
        If you are seeing this page after clicking a link sent to you via email, make
        sure you only click the confirmation link once, and that you open the
        validation link in the same client you're logging in from.
    </p>
    <p>
        Try logging in again from your Matrix client and if the problem persists
        please contact the server's administrator.
    </p>
    <p>Error: <code>{{ error }}</code></p>

    <script type="text/javascript">
        // Error handling to support Auth0 errors that we might get through a GET request
        // to the validation endpoint. If an error is provided, it's either going to be
        // located in the query string or in a query string-like URI fragment.
        // We try to locate the error from any of these two locations, but if we can't
        // we just don't print anything specific.
        let searchStr = "";
        if (window.location.search) {
            // window.location.searchParams isn't always defined when
            // window.location.search is, so it's more reliable to parse the latter.
            searchStr = window.location.search;
        } else if (window.location.hash) {
            // Replace the # with a ? so that URLSearchParams does the right thing and
            // doesn't parse the first parameter incorrectly.
            searchStr = window.location.hash.replace("#", "?");
        }

        // We might end up with no error in the URL, so we need to check if we have one
        // to print one.
        let errorDesc = new URLSearchParams(searchStr).get("error_description")
        if (errorDesc) {
            document.getElementById("errormsg").innerText = errorDesc;
        }
    </script>
{% endif %}
</body>
</html>

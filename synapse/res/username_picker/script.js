let inputField = document.getElementById("field-username");
let inputForm = document.getElementById("form");
let submitButton = document.getElementById("button-submit");
let message = document.getElementById("message");

// Submit username and receive response
function showMessage(messageText) {
    // Unhide the message text
    message.classList.remove("hidden");

    message.textContent = messageText;
};

function doSubmit() {
    showMessage("Success. Please wait a moment for your browser to redirect.");

    // remove the event handler before re-submitting the form.
    delete inputForm.onsubmit;
    inputForm.submit();
}

function onResponse(response) {
    // Display message
    showMessage(response);

    // Enable submit button and input field
    submitButton.classList.remove('button--disabled');
    submitButton.value = "Submit";
};

let allowedUsernameCharacters = RegExp("[^a-z0-9\\.\\_\\=\\-\\/]");
function usernameIsValid(username) {
    return !allowedUsernameCharacters.test(username);
}
let allowedCharactersString = "lowercase letters, digits, ., _, -, /, =";

function buildQueryString(params) {
    return Object.keys(params)
        .map(k => encodeURIComponent(k) + '=' + encodeURIComponent(params[k]))
        .join('&');
}

function submitUsername(username) {
    if(username.length == 0) {
        onResponse("Please enter a username.");
        return;
    }
    if(!usernameIsValid(username)) {
        onResponse("Invalid username. Only the following characters are allowed: " + allowedCharactersString);
        return;
    }

    // if this browser doesn't support fetch, skip the availability check.
    if(!window.fetch) {
        doSubmit();
        return;
    }

    let check_uri = 'check?' + buildQueryString({"username": username});
    fetch(check_uri, {
        // include the cookie
        "credentials": "same-origin",
    }).then((response) => {
        if(!response.ok) {
            // for non-200 responses, raise the body of the response as an exception
            return response.text().then((text) => { throw text; });
        } else {
            return response.json();
        }
    }).then((json) => {
        if(json.error) {
            throw json.error;
        } else if(json.available) {
            doSubmit();
        } else {
            onResponse("This username is not available, please choose another.");
        }
    }).catch((err) => {
        onResponse("Error checking username availability: " + err);
    });
}

function clickSubmit() {
    event.preventDefault();
    if(submitButton.classList.contains('button--disabled')) { return; }

    // Disable submit button and input field
    submitButton.classList.add('button--disabled');

    // Submit username
    submitButton.value = "Checking...";
    submitUsername(inputField.value);
};

inputForm.onsubmit = clickSubmit;

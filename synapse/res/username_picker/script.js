let inputField = document.getElementById("field-username");
let inputForm = document.getElementById("form");
let submitButton = document.getElementById("button-submit");
let message = document.getElementById("message");

// Remove input field placeholder if the text field is not empty
let switchClass = function(input) {
  if (input.value.length > 0) {
    input.classList.add('has-contents');
  }
  else {
    input.classList.remove('has-contents');
  }
};

// Submit username and receive response
let showMessage = function(messageText) {
  // Unhide the message text
  message.classList.remove("hidden");

  message.innerHTML = messageText;
};

let onResponse = function(response, success) {
  // Display message
  showMessage(response);

  if(success) {
    inputForm.submit();
    return;
  }

  // Enable submit button and input field
  submitButton.classList.remove('button--disabled');
  submitButton.value = "Submit"
};

let allowedUsernameCharacters = RegExp("[^a-z0-9\\.\\_\\=\\-\\/]");
let usernameIsValid = function(username) {
  return !allowedUsernameCharacters.test(username);
}
let allowedCharactersString = "" +
"lowercase letters, " +
"digits, " +
"<code>.</code>, " +
"<code>_</code>, " +
"<code>-</code>, " +
"<code>/</code>, " +
"<code>=</code>";

let buildQueryString = function(params) {
    return Object.keys(params)
        .map(k => encodeURIComponent(k) + '=' + encodeURIComponent(params[k]))
        .join('&');
}

let submitUsername = function(username) {
  if(username.length == 0) {
    onResponse("Please enter a username.", false);
    return;
  }
  if(!usernameIsValid(username)) {
    onResponse("Invalid username. Only the following characters are allowed: " + allowedCharactersString, false);
    return;
  }

    let check_uri = 'check?' + buildQueryString({"username": username});
    fetch(check_uri, {
        "credentials": "include",
    }).then((response) => {
        if(!response.ok) {
            // for non-200 responses, raise the body of the response as an exception
            return response.text().then((text) => { throw text });
        } else {
            return response.json()
        }
    }).then((json) => {
        if(json.error) {
            throw json.error;
        } else if(json.available) {
            onResponse("Success. Please wait a moment for your browser to redirect.", true);
        } else {
            onResponse("This username is not available, please choose another.", false);
        }
    }).catch((err) => {
        onResponse("Error checking username availability: " + err, false);
    });
}

let clickSubmit = function() {
  if(submitButton.classList.contains('button--disabled')) { return; }

  // Disable submit button and input field
  submitButton.classList.add('button--disabled');

  // Submit username
  submitButton.value = "Checking...";
  submitUsername(inputField.value);
};

submitButton.onclick = clickSubmit;

// Listen for events on inputField
inputField.addEventListener('keypress', function(event) {
  // Listen for Enter on input field
  if(event.which === 13) {
    event.preventDefault();
    clickSubmit();
    return true;
  }
  switchClass(inputField);
});
inputField.addEventListener('change', function() {
  switchClass(inputField);
});


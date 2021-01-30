const usernameField = document.getElementById("field-username");

function throttle(fn, wait) {
    let timeout;
    return function() {
        const args = Array.from(arguments);
        if (timeout) {
            clearTimeout(timeout);
        }
        timeout = setTimeout(fn.bind.apply(fn, [null].concat(args)), wait);
    }
}

function checkUsernameAvailable(username) {
    let check_uri = 'check?username=' + encodeURIComponent(username);
    return fetch(check_uri, {
        // include the cookie
        "credentials": "same-origin",
    }).then((response) => {
        if(!response.ok) {
            // for non-200 responses, raise the body of the response as an exception
            return response.text().then((text) => { throw new Error(text); });
        } else {
            return response.json();
        }
    }).then((json) => {
        if(json.error) {
            return {message: json.error};
        } else if(json.available) {
            return {available: true};
        } else {
            return {message: username + " is not available, please choose another."};
        }
    });
}

function validateUsername(username) {
    usernameField.setCustomValidity("");
    if (usernameField.validity.valueMissing) {
        usernameField.setCustomValidity("Please provide a username");
        return;
    }
    if (usernameField.validity.patternMismatch) {
        usernameField.setCustomValidity("Invalid username, please only use " + allowedCharactersString);
        return;
    }
    usernameField.setCustomValidity("Checking if username is available …");
    throttledCheckUsernameAvailable(username);
}

const throttledCheckUsernameAvailable = throttle(function(username) {
    const handleError =  function(err) {
        // don't prevent form submission on error
        usernameField.setCustomValidity("");
        console.log(err.message);
    };
    try {
        checkUsernameAvailable(username).then(function(result) {
            if (!result.available) {
                usernameField.setCustomValidity(result.message);
                usernameField.reportValidity();
            } else {
                usernameField.setCustomValidity("");
            }
        }, handleError);
    } catch (err) {
        handleError(err);
    }
}, 500);

usernameField.addEventListener("input", function(evt) {
    validateUsername(usernameField.value);
});
usernameField.addEventListener("change", function(evt) {
    validateUsername(usernameField.value);
});

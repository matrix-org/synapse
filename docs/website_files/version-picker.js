
const dropdown = document.querySelector('.version-picker .dropdown');
const dropdownMenu = dropdown.querySelector('.dropdown-menu');

fetchVersions(dropdown, dropdownMenu).then(() => {
    initializeVersionDropdown(dropdown, dropdownMenu);
});

/**
 * Initialize the dropdown functionality for version selection.
 * 
 * @param {Element} dropdown - The dropdown element.
 * @param {Element} dropdownMenu - The dropdown menu element.
 */
function initializeVersionDropdown(dropdown, dropdownMenu) {
    // Toggle the dropdown menu on click
    dropdown.addEventListener('click', function () {
        this.setAttribute('tabindex', 1);
        this.classList.toggle('active');
        dropdownMenu.style.display = (dropdownMenu.style.display === 'block') ? 'none' : 'block';
    });
  
    // Remove the 'active' class and hide the dropdown menu on focusout
    dropdown.addEventListener('focusout', function () {
        this.classList.remove('active');
        dropdownMenu.style.display = 'none';
    });
  
    // Handle item selection within the dropdown menu
    const dropdownMenuItems = dropdownMenu.querySelectorAll('li');    
    dropdownMenuItems.forEach(function (item) {
        item.addEventListener('click', function () {
            dropdownMenuItems.forEach(function (item) {
                item.classList.remove('active');
            });
            this.classList.add('active');
            dropdown.querySelector('span').textContent = this.textContent;
            dropdown.querySelector('input').value = this.getAttribute('id');

            window.location.href = changeVersion(window.location.href, this.textContent);
        });
    });
};

/**
 * This function fetches the available versions from a GitHub repository
 * and inserts them into the version picker.
 * 
 * @param {Element} dropdown - The dropdown element.
 * @param {Element} dropdownMenu - The dropdown menu element.
 * @returns {Promise<Array<string>>} A promise that resolves with an array of available versions.
 */
function fetchVersions(dropdown, dropdownMenu) {
    return new Promise((resolve, reject) => {
        window.addEventListener("load", () => {

            fetch("https://api.github.com/repos/matrix-org/synapse/git/trees/gh-pages", {
                cache: "force-cache",
            }).then(res => 
                res.json()
            ).then(resObject => {
                const excluded = ['dev-docs', 'v1.91.0', 'v1.80.0', 'v1.69.0'];
                const tree = resObject.tree.filter(item => item.type === "tree" && !excluded.includes(item.path));
                const versions = tree.map(item => item.path).sort(sortVersions);

                // Create a list of <li> items for versions
                versions.forEach((version) => {
                    const li = document.createElement("li");
                    li.textContent = version;
                    li.id = version;
    
                    if (window.SYNAPSE_VERSION === version) {
                        li.classList.add('active');
                        dropdown.querySelector('span').textContent = version;
                        dropdown.querySelector('input').value = version;
                    }
    
                    dropdownMenu.appendChild(li);
                });

                resolve(versions);

            }).catch(ex => {
                console.error("Failed to fetch version data", ex);
                reject(ex);
            })
        });
    });
}

/**
 * Custom sorting function to sort an array of version strings.
 *
 * @param {string} a - The first version string to compare.
 * @param {string} b - The second version string to compare.
 * @returns {number} - A negative number if a should come before b, a positive number if b should come before a, or 0 if they are equal.
 */
function sortVersions(a, b) {
    // Put 'develop' and 'latest' at the top
    if (a === 'develop' || a === 'latest') return -1;
    if (b === 'develop' || b === 'latest') return 1;

    const versionA = (a.match(/v\d+(\.\d+)+/) || [])[0];
    const versionB = (b.match(/v\d+(\.\d+)+/) || [])[0];

    return versionB.localeCompare(versionA);
}

/**
 * Change the version in a URL path.
 *
 * @param {string} url - The original URL to be modified.
 * @param {string} newVersion - The new version to replace the existing version in the URL.
 * @returns {string} The updated URL with the new version.
 */
function changeVersion(url, newVersion) {
    const parsedURL = new URL(url);
    const pathSegments = parsedURL.pathname.split('/');
  
    // Modify the version
    pathSegments[2] = newVersion;

    // Reconstruct the URL
    parsedURL.pathname = pathSegments.join('/');
  
    return parsedURL.href;
}
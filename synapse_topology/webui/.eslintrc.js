const path = require('path');

// get the path of the js-sdk so we can extend the config
// eslint supports loading extended configs by module,
// but only if they come from a module that starts with eslint-config-
// So we load the filename directly (and it could be in node_modules/
// or or ../node_modules/ etc)

module.exports = {
    parser: "babel-eslint",
    plugins: [
        "react",
        "babel"
    ],
    env: {
        es6: true,
    },
    parserOptions: {
        ecmaFeatures: {
            jsx: true,
        }
    },
    rules: {
        // rules we've always adhered to or now do
        "max-len": ["error", {
            code: 90,
            ignoreComments: true,
        }],
        curly: ["error", "multi-line"],
        "prefer-const": ["error"],
        "comma-dangle": ["error", {
            arrays: "always-multiline",
            objects: "always-multiline",
            imports: "always-multiline",
            exports: "always-multiline",
            functions: "always-multiline",
        }],

        // loosen jsdoc requirements a little
        "require-jsdoc": ["error", {
            require: {
                FunctionDeclaration: false,
            }
        }],
        "valid-jsdoc": ["error", {
            requireParamDescription: false,
            requireReturn: false,
            requireReturnDescription: false,
        }],

        // rules we do not want from eslint-recommended
        "no-console": ["off"],
        "no-constant-condition": ["off"],
        "no-empty": ["error", { "allowEmptyCatch": true }],

        // rules we do not want from the google styleguide
        "object-curly-spacing": ["off"],
        "spaced-comment": ["off"],
        "guard-for-in": ["off"],

        // in principle we prefer single quotes, but life is too short
        quotes: ["off"],

        // rules we'd ideally like to adhere to, but the current
        // code does not (in most cases because it's still ES5)
        // we set these to warnings, and assert that the number
        // of warnings doesn't exceed a given threshold
        "no-var": ["warn"],
        "brace-style": ["warn", "1tbs", { "allowSingleLine": true }],
        "prefer-rest-params": ["warn"],
        "prefer-spread": ["warn"],
        "padded-blocks": ["warn"],
        "no-extend-native": ["warn"],
        "camelcase": ["warn"],
        "no-multi-spaces": ["error", { "ignoreEOLComments": true }],
        "space-before-function-paren": ["error", {
            "anonymous": "never",
            "named": "never",
            "asyncArrow": "always",
        }],
        "arrow-parens": "off",

        // eslint's built in no-invalid-this rule breaks with class properties
        "no-invalid-this": "off",
        // so we replace it with a version that is class property aware
        "babel/no-invalid-this": "error",

        // We appear to follow this most of the time, so let's enforce it instead
        // of occasionally following it (or catching it in review)
        "keyword-spacing": "error",

        /** react **/
        // This just uses the react plugin to help eslint known when
        // variables have been used in JSX
        "react/jsx-uses-vars": "error",
        // Don't mark React as unused if we're using JSX
        "react/jsx-uses-react": "error",

        // bind or arrow function in props causes performance issues
        // (but we currently use them in some places)
        // It's disabled here, but we should using it sparingly.
        "react/jsx-no-bind": "off",
        "react/jsx-key": ["error"],

        // Components in JSX should always be defined.
        "react/jsx-no-undef": "error",

        // Assert no spacing in JSX curly brackets
        // <Element prop={ consideredError} prop={notConsideredError} />
        //
        // https://github.com/yannickcr/eslint-plugin-react/blob/HEAD/docs/rules/jsx-curly-spacing.md
        //
        // Disabled for now - if anything we'd like to *enforce* spacing in JSX
        // curly brackets for legibility, but in practice it's not clear that the
        // consistency particularly improves legibility here. --Matthew
        //
        // "react/jsx-curly-spacing": ["error", {"when": "never", "children": {"when": "always"}}],

        // Assert spacing before self-closing JSX tags, and no spacing before or
        // after the closing slash, and no spacing after the opening bracket of
        // the opening tag or closing tag.
        //
        // https://github.com/yannickcr/eslint-plugin-react/blob/HEAD/docs/rules/jsx-tag-spacing.md
        "react/jsx-tag-spacing": ["error"],
    },
    settings: {
        flowtype: {
            onlyFilesWithFlowAnnotation: true
        },
    },
};

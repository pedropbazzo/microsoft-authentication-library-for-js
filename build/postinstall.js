let exec = require("child_process").exec;

if (parseInt(process.env.RUNNING_NODE_CI)) {
    console.log("Running scoped bootstrap");
    exec("lerna --scope @azure/* --scope msal --scope vanilla-js-test* --scope @azuread/* --ignore @azure/msal-angularjs bootstrap", function (error, stdout, stderr) {
        if (stdout) {
            console.log('stdout' + stdout);
        }
        console.error('stderr: ' + stderr);
        if (error !== null) {
             console.log('exec error: ' + error);
        }
    });
} else {
    console.log("Running full bootstrap");
    exec("lerna bootstrap", function (error, stdout, stderr) {
        if (stdout) {
            console.log('stdout' + stdout);
        }
        console.error('stderr: ' + stderr);
        if (error !== null) {
             console.log('exec error: ' + error);
        }
    });
}

const { execSync } = require('child_process');

// Git identity for simple-git commits — fixes "Please tell me who you are"
try {
    execSync('git config --global user.name "Git Server"');
    execSync('git config --global user.email "git@localhost"');
    execSync('git config --global init.defaultBranch main');
    console.log('✅ Git identity configured');
} catch (err) {
    console.error('⚠️ Git config failed:', err.message);
}

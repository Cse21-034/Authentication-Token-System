<?php
// Set up a simple PHP web server to run the authentication system
echo "PHP Authentication Token System Server" . PHP_EOL;
echo "----------------------------------------" . PHP_EOL;
echo "Starting server on http://0.0.0.0:5000" . PHP_EOL;
echo "Press Ctrl+C to stop" . PHP_EOL;

// Set up database if it doesn't exist
if (!file_exists('db_setup_completed.txt')) {
    echo "Setting up database tables..." . PHP_EOL;
    // Include database setup script
    include 'setup_database.php';
    // Create a marker file to indicate that setup is complete
    file_put_contents('db_setup_completed.txt', date('Y-m-d H:i:s'));
    echo "Database setup completed" . PHP_EOL;
}

// Start the PHP built-in web server
$command = 'php -S 0.0.0.0:5000 -t ' . __DIR__;
passthru($command);
?>
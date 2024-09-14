<?php
require __DIR__ . '/vendor/autoload.php';
use \Firebase\JWT\JWT;
use \Firebase\JWT\Key;

// Function to get bearer token from header
function getBearerToken() {
    $headers = getallheaders();
    if (isset($headers['Authorization'])) {
        if (preg_match('/Bearer\s(\S+)/', $headers['Authorization'], $matches)) {
            return $matches[1];
        }
    }
    return null;
}

// Function to validate JWT token
function validateToken($token, $secret_key) {
    try {
        $decoded = JWT::decode($token, new Key($secret_key, 'HS256'));
        return $decoded->user_id;
    } catch (Exception $e) {
        return false;
    }
}

// Your secret key (must match the one in your Flask app)
$secret_key = 'your_secret_key';  // Replace with your actual secret key

// Get the image path from the request
$image_path = $_SERVER['REQUEST_URI'];
$image_path = ltrim(parse_url($image_path, PHP_URL_PATH), '/');
$image_path = str_replace('uploads/', '', $image_path);

// Full path to the image
$full_path = '/var/www/auftrag.immoyes.com/upload/' . $image_path;

// Validate token
$token = getBearerToken();
if (!$token) {
    header("HTTP/1.0 401 Unauthorized");
    echo "No token provided";
    exit;
}

$user_id = validateToken($token, $secret_key);
if (!$user_id) {
    header("HTTP/1.0 401 Unauthorized");
    echo "Invalid token";
    exit;
}

// Check if the file exists and is within the uploads directory
if (file_exists($full_path) && strpos(realpath($full_path), '/var/www/auftrag.immoyes.com/upload/') === 0) {
    // Check if the user has permission to access this file
    // You may need to implement this check based on your database structure
    // For example, check if the image belongs to a project owned by the user
    if (userHasPermission($user_id, $image_path)) {
        $mime = mime_content_type($full_path);
        header("Content-Type: $mime");
        readfile($full_path);
    } else {
        header("HTTP/1.0 403 Forbidden");
        echo "Access denied";
    }
} else {
    header("HTTP/1.0 404 Not Found");
    echo "File not found";
}

// Function to check if user has permission to access the file
// You need to implement this based on your database structure
function userHasPermission($user_id, $image_path) {
    // Connect to your database
    $db = new PDO('mysql:host=w0108f4a.kasserver.com;dbname=d0414046', 'd0414046', 'WS2A99X53jMsvsD7jWeV');
    
    // Extract project ID from image path (assuming format: user_email/project_id/filename)
    $path_parts = explode('/', $image_path);
    if (count($path_parts) >= 2) {
        $project_id = $path_parts[1];
        
        // Check if the project belongs to the user
        $stmt = $db->prepare("SELECT COUNT(*) FROM Project WHERE id = ? AND user_id = ?");
        $stmt->execute([$project_id, $user_id]);
        $count = $stmt->fetchColumn();
        
        return $count > 0;
    }
    
    return false;
}

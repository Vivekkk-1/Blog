<?php
// Include config file
include "assest/head.php";

// Initialize variables and errors
$email = $email_err = $success_msg = "";

// Processing the form data
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Check if email is empty
    if (empty(trim($_POST["email"]))) {
        $email_err = "Please enter your email.";
    } else {
        $email = trim($_POST["email"]);
    }

    // Check if email exists in the database
    if (empty($email_err)) {
        $sql = "SELECT id, username, email FROM users WHERE email = :email";
        
        if ($stmt = $pdo->prepare($sql)) {
            $stmt->bindParam(":email", $param_email, PDO::PARAM_STR);
            $param_email = $email;

            if ($stmt->execute()) {
                if ($stmt->rowCount() == 1) {
                    $row = $stmt->fetch();
                    $id = $row["id"];
                    $username = $row["username"];

                    // Generate a random password reset token
                    $reset_token = bin2hex(random_bytes(32));

                    // Store the token in the database with an expiration date
                    $expiry_time = date("Y-m-d H:i:s", strtotime("+1 hour"));
                    $sql = "INSERT INTO password_resets (user_id, token, expires_at) VALUES (:user_id, :token, :expires_at)";
                    if ($stmt = $pdo->prepare($sql)) {
                        $stmt->bindParam(":user_id", $id, PDO::PARAM_INT);
                        $stmt->bindParam(":token", $reset_token, PDO::PARAM_STR);
                        $stmt->bindParam(":expires_at", $expiry_time, PDO::PARAM_STR);
                        
                        if ($stmt->execute()) {
                            // Send reset link to the user's email
                            $reset_link = "http://yourdomain.com/reset_password.php?token=$reset_token";
                            $subject = "Password Reset Request";
                            $message = "Hello $username, click on the link below to reset your password:\n$reset_link";
                            $headers = "From: noreply@yourdomain.com";

                            // Send the email
                            if (mail($email, $subject, $message, $headers)) {
                                $success_msg = "Password reset link has been sent to your email.";
                            } else {
                                $email_err = "Something went wrong while sending the email.";
                            }
                        } else {
                            $email_err = "Something went wrong while storing the reset token.";
                        }
                    }
                } else {
                    $email_err = "No account found with that email address.";
                }
            }
        }
    }

    // Close connection
    unset($pdo);
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="icon" href="img/logo/flogo.png" sizes="32x32" type="image/png">
    <link rel="stylesheet" href="css/bootstrap.min.css">
    <link rel="stylesheet" href="css/font-awesome.css">
    <link type="text/css" rel="stylesheet" href="css/style.css" />
    <title>Forgot Password</title>
</head>
<body class="d-flex flex-column min-vh-100">
    <!-- Header -->
    <?php include "assest/header.php"; ?>

    <!-- Main -->
    <main class="main">
        <div class="section jumbotron mb-0 h-100">
            <div class="container d-flex flex-column justify-content-center align-items-center h-100">
                <div class="wrapper bg-white rounded px-4 py-4 w-50">
                    <h2>Forgot Password</h2>
                    <p>Enter your email address to receive a password reset link.</p>

                    <?php if (!empty($email_err)): ?>
                        <div class="alert alert-danger"><?= $email_err; ?></div>
                    <?php endif; ?>
                    <?php if (!empty($success_msg)): ?>
                        <div class="alert alert-success"><?= $success_msg; ?></div>
                    <?php endif; ?>

                    <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="POST">
                        <div class="form-group">
                            <label>Email</label>
                            <input type="email" name="email" class="form-control <?= (!empty($email_err)) ? 'is-invalid' : ''; ?>" value="">
                            <span class="invalid-feedback"><?= $email_err; ?></span>
                        </div>
                        <div class="form-group">
                            <input type="submit" class="btn btn-success" value="Send Reset Link">
                        </div>
                    </form>
                </div>
            </div>
        </div>
    </main>

    <!-- Footer -->
    <!-- <?php include "assest/footer.php" ?> -->
    <script src="https://code.jquery.com/jquery-3.4.1.slim.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/popper.js@1.16.0/dist/umd/popper.min.js"></script>
    <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.4.1/js/bootstrap.min.js"></script>
</body>
</html>

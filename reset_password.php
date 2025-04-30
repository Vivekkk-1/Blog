<?php
// Include config file
include "assest/head.php";

// Initialize variables and errors
$new_password = $confirm_password = "";
$new_password_err = $confirm_password_err = "";

// Check if the reset token is provided
if (isset($_GET["token"])) {
    $reset_token = $_GET["token"];
    // Validate token
    $sql = "SELECT * FROM password_resets WHERE token = :token AND expires_at > NOW()";

    if ($stmt = $pdo->prepare($sql)) {
        $stmt->bindParam(":token", $reset_token, PDO::PARAM_STR);
        if ($stmt->execute()) {
            if ($stmt->rowCount() == 1) {
                // Token is valid, user can reset password
                if ($_SERVER["REQUEST_METHOD"] == "POST") {
                    // Validate new password
                    if (empty(trim($_POST["new_password"]))) {
                        $new_password_err = "Please enter a new password.";
                    } else {
                        $new_password = trim($_POST["new_password"]);
                    }

                    // Validate confirm password
                    if (empty(trim($_POST["confirm_password"]))) {
                        $confirm_password_err = "Please confirm your new password.";
                    } else {
                        $confirm_password = trim($_POST["confirm_password"]);
                        if ($new_password != $confirm_password) {
                            $confirm_password_err = "Password confirmation doesn't match.";
                        }
                    }

                    // Check if no errors
                    if (empty($new_password_err) && empty($confirm_password_err)) {
                        // Get user id from password reset token
                        $row = $stmt->fetch();
                        $user_id = $row["user_id"];

                        // Hash the new password
                        $hashed_password = password_hash($new_password, PASSWORD_DEFAULT);

                        // Update the password in the database
                        $sql = "UPDATE users SET password = :password WHERE id = :id";
                        if ($stmt = $pdo->prepare($sql)) {
                            $stmt->bindParam(":password", $hashed_password, PDO::PARAM_STR);
                            $stmt->bindParam(":id", $user_id, PDO::PARAM_INT);

                            if ($stmt->execute()) {
                                // Password updated successfully, redirect to login page
                                header("location: login.php");
                            } else {
                                echo "Oops! Something went wrong. Please try again later.";
                            }
                        }
                    }
                }
            } else {
                echo "This reset link has expired or is invalid.";
            }
        }
    }
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
    <title>Reset Password</title>
</head>
<body class="d-flex flex-column min-vh-100">
    <!-- Header -->
    <?php include "assest/header.php"; ?>

    <!-- Main -->
    <main class="main">
        <div class="section jumbotron mb-0 h-100">
            <div class="container d-flex flex-column justify-content-center align-items-center h-100">
                <div class="wrapper bg-white rounded px-4 py-4 w-50">
                    <h2>Reset Password</h2>

                    <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="POST">
                        <div class="form-group">
                            <label>New Password</label>
                            <input type="password" name="new_password" class="form-control <?= (!empty($new_password_err)) ? 'is-invalid' : ''; ?>" value="">
                            <span class="invalid-feedback"><?= $new_password_err; ?></span>
                        </div>
                        <div class="form-group">
                            <label>Confirm New Password</label>
                            <input type="password" name="confirm_password" class="form-control <?= (!empty($confirm_password_err)) ? 'is-invalid' : ''; ?>" value="">
                            <span class="invalid-feedback"><?= $confirm_password_err; ?></span>
                        </div>
                        <div class="form-group">
                            <input type="submit" class="btn btn-success" value="Reset Password">
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

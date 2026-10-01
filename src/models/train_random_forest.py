import pandas as pd

# train_test_split divides the dataset into training and testing portions.
from sklearn.model_selection import train_test_split

# RandomForestClassifier creates an ensemble of decision trees.
from sklearn.ensemble import RandomForestClassifier

# These functions calculate different model performance metrics.
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix
)


# Location of our feature dataset.
DATA_FILE = "data/processed/url_features.csv"


# These are the 14 URL features that the ML model is allowed to use.
# We deliberately exclude:
#   url              -> raw URL, not used directly by this model
#   type             -> original class name; including it would cause leakage
#   binary_label     -> target
#   multiclass_label -> another target
FEATURE_COLUMNS = [
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",
    "dot_count",
    "hyphen_count",
    "digit_count",
    "special_char_count",
    "subdomain_count",
    "contains_ip",
    "uses_https",
    "contains_at",
    "contains_double_slash",
    "suspicious_keyword_count"
]


def load_dataset():
    """
    Loads the processed URL feature dataset.

    Returns:
        X -> the 14 input features
        y -> the binary target label
    """

    # Read the CSV file into a pandas DataFrame.
    df = pd.read_csv(DATA_FILE)

    print(f"Total samples: {len(df)}")

    # Select only the features that the model is allowed to see.
    X = df[FEATURE_COLUMNS]

    # Binary classification target:
    # 0 = benign
    # 1 = malicious
    y = df["binary_label"]

    return X, y


def split_dataset(X, y):
    """
    Splits the data into training and testing sets.

    80% of the data is used for training.
    20% is kept unseen for testing.

    stratify=y keeps the class proportions similar
    in both sets.
    """

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=42,
        stratify=y
    )

    return X_train, X_test, y_train, y_test


def train_model(X_train, y_train):
    """
    Creates and trains the Random Forest model.

    Random Forest builds many decision trees and combines
    their predictions to produce the final prediction.
    """

    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=None,
        min_samples_split=2,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1
    )

    print("\nTraining Random Forest...")

    # Train all decision trees using the training data.
    model.fit(X_train, y_train)

    return model


def evaluate_model(model, X_test, y_test):
    """
    Evaluates the trained model using the unseen test data.

    Calculates:
        Accuracy
        Precision
        Recall
        F1 score
        Classification report
        Confusion matrix
    """

    # Ask the trained model to predict labels for unseen URLs.
    y_pred = model.predict(X_test)

    # Calculate overall accuracy.
    accuracy = accuracy_score(y_test, y_pred)

    # Precision tells us how many URLs predicted as malicious
    # were actually malicious.
    precision = precision_score(
        y_test,
        y_pred,
        zero_division=0
    )

    # Recall tells us how many actual malicious URLs
    # were successfully detected.
    recall = recall_score(
        y_test,
        y_pred,
        zero_division=0
    )

    # F1 combines precision and recall.
    f1 = f1_score(
        y_test,
        y_pred,
        zero_division=0
    )

    print("\n================================")
    print("RANDOM FOREST RESULTS")
    print("================================")

    print(f"Accuracy : {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall   : {recall:.4f}")
    print(f"F1 Score : {f1:.4f}")

    print("\nClassification Report:")

    print(
        classification_report(
            y_test,
            y_pred,
            target_names=["Benign", "Malicious"],
            zero_division=0
        )
    )

    print("Confusion Matrix:")

    print(confusion_matrix(y_test, y_pred))


def main():
    """
    Main function that executes the complete Random Forest pipeline.

    Workflow:

    1. Load dataset
    2. Separate features and target
    3. Split into training/testing data
    4. Train Random Forest
    5. Evaluate the model
    """

    print("Loading feature dataset...")

    # Load the features and target labels.
    X, y = load_dataset()

    print(f"Features: {X.shape[1]}")
    print(f"Samples: {X.shape[0]}")

    print("\nClass distribution:")
    print(y.value_counts())

    # Create the training and testing datasets.
    X_train, X_test, y_train, y_test = split_dataset(X, y)

    print("\nDataset split:")
    print(f"Training samples: {len(X_train)}")
    print(f"Testing samples: {len(X_test)}")

    # Train the Random Forest model.
    model = train_model(X_train, y_train)

    # Evaluate the trained model.
    evaluate_model(model, X_test, y_test)


# This makes sure main() runs only when this file
# is executed directly.
if __name__ == "__main__":
    main()

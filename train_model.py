import pandas as pd
import joblib

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

data = {
    "email": [
        "Congratulations you won a free prize claim now",
        "Click here to get free money",
        "Urgent your account has been suspended verify now",
        "You have been selected for a lottery reward",
        "Win cash now limited time offer",
        "Dear customer update your bank account immediately",
        "Your password will expire verify your login",
        "Claim your free gift card today",
        "Hi Hari your interview is scheduled for Monday",
        "Please find the attached project report",
        "Can we meet tomorrow for the assignment discussion",
        "Your class schedule has been updated",
        "Thank you for applying to the software engineer role",
        "The meeting is moved to 3 PM",
        "Your order has been shipped successfully",
        "Professor shared the lecture notes for this week",
    ],
    "label": [
        "spam", "spam", "spam", "spam",
        "spam", "spam", "spam", "spam",
        "ham", "ham", "ham", "ham",
        "ham", "ham", "ham", "ham"
    ]
}

df = pd.DataFrame(data)

X = df["email"]
y = df["label"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.25, random_state=42
)

model = Pipeline([
    ("tfidf", TfidfVectorizer()),
    ("classifier", MultinomialNB())
])

model.fit(X_train, y_train)

predictions = model.predict(X_test)
accuracy = accuracy_score(y_test, predictions)

joblib.dump(model, "spam_model.pkl")

print("Model trained successfully!")
print(f"Accuracy: {accuracy * 100:.2f}%")
print("Saved as spam_model.pkl")
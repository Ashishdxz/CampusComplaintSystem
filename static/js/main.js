// Client-side interactions & validation for Campus Complaint System

document.addEventListener("DOMContentLoaded", function () {
    const complaintForm = document.getElementById("complaintForm");
    const submitBtn = document.getElementById("submitBtn");

    if (complaintForm) {
        complaintForm.addEventListener("submit", function (e) {
            const titleInput = document.getElementById("title");
            const categorySelect = document.getElementById("category");
            const descInput = document.getElementById("description");

            const title = titleInput.value.trim();
            const category = categorySelect.value;
            const description = descInput.value.trim();

            // Simple validation check
            if (!title) {
                alert("Please enter a complaint title.");
                titleInput.focus();
                e.preventDefault();
                return;
            }

            if (!category) {
                alert("Please select a category from the dropdown.");
                categorySelect.focus();
                e.preventDefault();
                return;
            }

            if (!description || description.length < 10) {
                alert("Please provide a more detailed description (at least 10 characters).");
                descInput.focus();
                e.preventDefault();
                return;
            }

            // Prevent duplicate clicks by temporarily changing the button state
            if (submitBtn) {
                submitBtn.disabled = true;
                submitBtn.innerText = "Submitting Anonymously...";
            }
        });
    }
});

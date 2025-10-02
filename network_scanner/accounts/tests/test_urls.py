from django.urls import reverse, resolve

def test_urls_resolve():
    assert resolve(reverse("register")).url_name == "register"
    assert resolve(reverse("logout")).url_name == "logout"
    assert resolve(reverse("profile", kwargs={"id": 1})).url_name == "profile"
    assert resolve(reverse("activity")).url_name == "activity"
    assert resolve(reverse("change-password")).url_name == "change-password"

from django import forms


class VulnerabilityAgentForm(forms.Form):
    message = forms.CharField(
        required=True,
        widget=forms.TextInput(
            attrs={"placeholder": "Ask the VulnerableCode Agent anything you need."}
        ),
    )

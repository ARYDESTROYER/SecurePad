from django import forms
from .models import SecretItem


class SecretItemForm(forms.ModelForm):
    class Meta:
        model = SecretItem
        fields = ('title', 'content', 'item_type')
        widgets = {
            'content': forms.Textarea(attrs={'rows': 6}),
        }

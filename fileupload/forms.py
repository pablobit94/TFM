from django import forms

class SingleFileUploadForm(forms.Form):
    file = forms.FileField(label='Select files')

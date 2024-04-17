namespace Keepass2Client.Entities;

public enum FormFieldType {FFTradio, FFTusername, FFTtext, FFTpassword, FFTselect, FFTcheckbox};
public record FormField(string Name, string Value, FormFieldType Type);
public record Group(string Title);

public record Entry(string Title, string UniqueId, string UsernameName, List<FormField> FormFieldList, Group? Parent, string IconImageData)
{
    public string? Username => FormFieldList.FirstOrDefault(field => field.Type == FormFieldType.FFTusername)?.Value;
    public string? Password => FormFieldList.FirstOrDefault(field => field.Type == FormFieldType.FFTpassword)?.Value;
    public byte[] Icon => Convert.FromBase64String(IconImageData);
};

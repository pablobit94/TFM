import mongoengine as me

class FileHash(me.Document):
    hash = me.StringField(required=True, unique=True)
    virustotal_status = me.DictField()
    hybrid_analysis_status = me.DictField()

from table import Table
from table.columns import Column
from models import Machine
from models import Software

class PostTableSoftware(Table):
    Name = Column(field='name', header=u'Software')
    Version = Column(field='version', header=u'Version')
    Publisher = Column(field='publisher', header=u'Publisher')

    class Meta:
        model = Software
from django.db import models

# Create your models here.


class TimeStampedModel(models.Model):
    """
       An abstract base class model that provides self-updating
       ``created`` and ``modified`` fields.
       """
    created_at = models.DateTimeField(_('created'), auto_now_add=True, editable=False)
    modified_at = models.DateTimeField(_('modified'), auto_now=True)

    class Meta:
        abstract = True


class PhoneBook(TimeStampedModel):
    first_name = models.CharField(max_length=512, null=True, blank=True)
    last_name = models.CharField(max_length=64, null=True, blank=True)
    state = models.CharField(max_length=128, null=True, blank=True)
    phone_number = models.CharField(max_length=64, null=True, blank=True)

    def __str__(self):
        """
        Use to display first name of entry with number.
        """
        return self.first_name +"-"+ self.phone_number




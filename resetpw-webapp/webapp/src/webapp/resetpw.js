tool_obj =
{
	testMode: false,

	title: "RESET PASSWORD",

	start: function(obj, data)
	{
		setTitle(obj.title);

		setupAlert("resetpw_alertReset");
		setupAlert("resetpw_alertNotResetNotFound");
		setupAlert("resetpw_alertNotResetTooMany");
		$("#resetpw_send").on('click', function(event){obj.send(obj);});
	},

	stop: function(obj, save)
	{
	},
	
	send: function(obj)
	{
		var data = new Object();
		data.email = $("#resetpw_email").val();
		requestCdp("resetpw_resetPassword", data, function(data)
		{
			$("#resetpw_email").val("");
			if (data.results.found == 0)
			{
				$("#resetpw_alertNotResetNotFound").dialog("open");
			}
			else if (data.results.found == 2)
			{
				$("#resetpw_alertNotResetTooMany").dialog("open");
			}
			else
			{
				$("#resetpw_email_sent").empty().text(data.results.email);
				$("#resetpw_alertReset").dialog("open");
			}
		});
		return true;
	}
};

completeToolLoad();

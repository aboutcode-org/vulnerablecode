var remove_toggled = false ;
var remove_vuln_toggled = false ;
function  addRemoveButtonsOnResolved()
{
    if (remove_toggled)
    {
        var delete_buttons = document.getElementsByClassName('delete is-small')
        for(var i = delete_buttons.length-1 ; i>=0 ; i--)
        {
            delete_buttons[i].remove();
        }
        remove_toggled = false;

    }
    else
    {
        var tags = document.getElementsByClassName('tag is-primary is-medium')
        for(var i = 0 ; i<tags.length ; i++)
        {
            let vuln_pk = extract_pk(tags[i].children[0].attributes['href'].nodeValue) ;
            // Do this in a cleaner way

            url = "../relations/resolved/" + {{object.pk}} + "/" + vuln_pk
            let btnHTML = `
            <form method="POST" action=${url}>
            {% csrf_token %}<input type="submit" class="delete is-small">
            </form>
            `

            tags[i].innerHTML += btnHTML;
        }
        remove_toggled = true ;
    }

}
function  addRemoveButtonsOnImpacted()
{
    if (remove_vuln_toggled)
    {
        var delete_buttons = document.getElementsByClassName('delete is-small')
        for(var i = delete_buttons.length-1 ; i>=0 ; i--)
        {
            delete_buttons[i].remove();
        }
        remove_vuln_toggled = false;

    }
    else
    {
        var tags = document.getElementsByClassName('tag is-danger is-medium')
        for(var i = 0 ; i<tags.length ; i++)
        {
            let vuln_pk = extract_pk(tags[i].children[0].attributes['href'].nodeValue) ;
            // Do this in a cleaner way

            url = "../relations/impacted/" + {{object.pk}} + "/" + vuln_pk
            let btnHTML = `
            <form method="POST" action=${url}>
            {% csrf_token %}<input type="submit" class="delete is-small">
            </form>
            `

            tags[i].innerHTML += btnHTML;
        }
        remove_vuln_toggled = true ;
    }

}



function extract_pk(url)
{
    let splitted_url = url.split('/')
    // eg value of url = "/vulnerabilities/5909"

    return splitted_url[splitted_url.length -1]
}
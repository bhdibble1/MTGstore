def order_confirmation_html(order, items):
    rows = "".join(
        f"<tr><td>{it.product.product_name}</td><td>{it.quantity}</td><td>${it.subtotal:.2f}</td></tr>"
        for it in items
    )
    return f"""
    <div style="font-family:Arial,sans-serif">
      <h2>Thanks for your order #{order.id}!</h2>
      <p>We’ll email you tracking when it ships.</p>
      <table cellpadding="6" cellspacing="0" border="1">
        <tr><th>Item</th><th>Qty</th><th>Subtotal</th></tr>
        {rows}
      </table>
      <p><strong>Total: ${order.total:.2f}</strong></p>
      <p>Questions? Reply to this email.</p>
    </div>
    """